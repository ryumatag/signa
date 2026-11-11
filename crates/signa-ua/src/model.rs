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

CANCEL is the core's to send and retransmit. The model only asks for it, and
decides what a CANCEL that arrives does to an INVITE it holds. A BYE goes in a
client transaction of the core's own, and what the model keeps is when it may
go and what it ends.

After this user agent sends a BYE, its dialog lingers until the BYE's
transaction ends, in what [RFC 5407 section 2] calls the Mortal state. A BYE
from the peer that crosses it gets a 200 there, and any other request a 481,
rather than the 481 of a dialog nobody knows ([RFC 5407 section 3.2.1]).

Where offers and answers go is the model's too, as [`crate::negotiation`]
says, though what they say is not. An answer the ACK of a 2xx owes comes from
outside, through [`Effect::PrepareAnswer`] and [`Model::answer_prepared`], so
that the model never waits for it.

TODO: Re-INVITEs are still to come.

[RFC 3261 section 17]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17
[RFC 5407 section 2]: https://www.rfc-editor.org/rfc/rfc5407.html#section-2
[RFC 5407 section 3.2.1]: https://www.rfc-editor.org/rfc/rfc5407.html#section-3.2.1
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
    transport::Flow,
};

use crate::{
    dialog::{
        Dialog, DialogError, DialogId, DialogKey, DialogPhase, Origin,
        OutOfOrder, Outgoing, RequestError, Sequence, request_dialog,
        response_tag,
    },
    error::Error,
    invite::{
        AttemptKey, AttemptResult, ByeIntent, CancelIntent, CancelResult,
        Direction, EndReason, ExchangeKey, ExchangeState, InviteAttempt,
        InviteExchange, InviteUsage, MergeKey, Provisional, Scope, UsageKey,
        UsagePhase, Withdrawal,
    },
    negotiation::{Body, Description, Negotiation},
    operation::{Completion, OperationId, Operations, Stage, SubmitError},
    plan::{Identity, InvitePlan, PlannedInvite},
    protocol::{self, Field, Malformed},
    retention::{
        AckBody, AckObligation, Bye, ReplayContext, ReplayId, ReplayKey,
        Retention, Retransmission, Source,
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
    /// Send a provisional response from 101 to 199 for an incoming INVITE,
    /// with a preview of the answer to its offer if given. It takes no
    /// authority, since it decides nothing.
    Provisional {
        exchange: ExchangeKey,
        status: StatusCode,
        preview: Option<Description>,
    },
    /// Reject an incoming INVITE with a final response from 300 to 699.
    Reject { authority: Authority, status: StatusCode },
    /// Send an initial INVITE built from a plan, which carries an offer.
    Invite { plan: Box<InvitePlan> },
    /// Cancel an INVITE this user agent sent, while it has no final
    /// response. The sessions its 2xx responses form are left alone.
    Cancel { attempt: AttemptKey },
    /// Give an INVITE this user agent sent up: cancel it, end the sessions
    /// it formed, and end each one a 2xx forms later.
    Abandon { attempt: AttemptKey },
    /// End a session with a BYE.
    Terminate { usage: UsageKey },
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
    /// responder, with `to_tag` on its To and `preview` as its body, then
    /// report the verdict with [`Model::provisional_done`]. `operation` is
    /// `None` when the UA sends it again on its own.
    SubmitProvisional {
        exchange: ExchangeKey,
        status: StatusCode,
        to_tag: Tag,
        preview: Option<Description>,
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
    /// Have the answer to `offer`, the offer of a received 2xx, prepared for
    /// its ACK, outside the driver and within a deadline, then report it with
    /// [`Model::answer_prepared`]. `usage` is the session the 2xx formed, or
    /// `None` for a 2xx the UA ends, whose answer is to reject the offer.
    PrepareAnswer {
        replay: ReplayKey,
        offer: Description,
        usage: Option<UsageKey>,
    },
    /// Send the ACK of a received 2xx, which [`Model::ack_request`] builds,
    /// then report the write with [`Model::ack_written`].
    SendAck { replay: ReplayKey },
    /// Send the ACK already sent for a 2xx again, for a copy of that 2xx.
    ResendAck { replay: ReplayKey },
    /// Send the BYE of a cleanup, which [`Model::bye_request`] builds, then
    /// report with [`Model::bye_done`] once the core has it or cannot take
    /// it. Nothing waits for the BYE's response.
    SendBye { replay: ReplayKey },
    /// Send the BYE that ends a session, which
    /// [`Model::session_bye_request`] builds. Report whether the core took
    /// it with [`Model::bye_started`], and then its response with
    /// [`Model::bye_answered`].
    SendSessionBye { usage: UsageKey },
    /// Ask the core to cancel the INVITE of an attempt, then report what it
    /// did with [`Model::cancel_done`].
    CancelInvite { attempt: AttemptKey, operation: Option<OperationId> },
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
    /// Its body is one the UA cannot tell the offer in, such as a multipart
    /// body. A 415 (RFC 3261 section 8.2.3).
    UnsupportedBody,
    /// Its CSeq is below the last one in its dialog, which RFC 3261 section
    /// 12.2.2 answers with a 500. So is one with the last number, by my
    /// policy (see `Dialog::remote_request`).
    OutOfOrder,
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
            Refusal::UnsupportedBody => 415,
            Refusal::SipsRequestUri => 416,
            Refusal::BadExtension => 420,
            Refusal::SipsNotAllowed => 480,
            Refusal::NoDialog => 481,
            Refusal::Merged => 482,
            Refusal::RouteSetTooLong
            | Refusal::Unsupported
            | Refusal::OutOfOrder
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
/// Why a usage ended outlives the notification too, see [`Model::ended`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    /// A provisional response formed an early dialog.
    EarlyDialog { dialog: DialogKey, usage: UsageKey },
    /// A 2xx confirmed the dialog. The ACK may still be owed, and the
    /// session descriptions may not be settled.
    DialogConfirmed { dialog: DialogKey, usage: UsageKey },
    /// The offer/answer exchange of a usage completed: the answer came, or
    /// this user agent's answer is fixed.
    NegotiationCompleted { usage: UsageKey },
    /// The offer/answer exchange of a usage failed, and the usage ends with
    /// a BYE next.
    NegotiationFailed { usage: UsageKey },
    /// The answer in a 2xx differs from the preview of it an unreliable
    /// provisional response carried, which RFC 3261 section 13.2.1 does not
    /// allow. The preview stays the answer.
    AnswerChanged { usage: UsageKey },
    /// No ACK came for the 2xx of an incoming INVITE by its deadline. The
    /// usage ends next.
    AckTimeout { usage: UsageKey },
    /// The usage ended.
    UsageEnded { usage: UsageKey, reason: EndReason },
    /// An attempt got a final response other than a 2xx, or its transaction
    /// failed, which ended its early dialogs.
    AttemptFailed { attempt: AttemptKey, error: Error },
    /// The caller gave an INVITE up before the application decided it, and
    /// the UA answered it with a 487.
    InviteWithdrawn { exchange: ExchangeKey },
}

/// How the UA takes a request in a dialog other than INVITE, ACK and CANCEL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InDialog {
    /// A BYE the UA took. It gets a 200 (RFC 3261 section 15.1.2).
    Bye,
    /// A request that changes nothing in the dialog, which RFC 3261 section
    /// 12.2.2 has answered as one outside it.
    Other,
}

/// A BYE on its way to the core, from the moment it is asked for until the
/// core has it or cannot take it.
#[derive(Clone, Copy, Debug)]
struct SendingBye {
    operation: Option<OperationId>,
    dialog: DialogKey,
    reason: EndReason,
    /// Whether the usage goes back to its phase before if the BYE never
    /// reaches the core, rather than end anyway, as at an ACK timeout.
    restore: bool,
}

/// A BYE the core took, whose response the runtime is to report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ByeStarted {
    pub(crate) dialog: DialogKey,
    pub(crate) operation: Option<OperationId>,
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
    /// Finds an incoming exchange from the early dialog its responses form,
    /// for a BYE the caller sends in it, until its final is committed.
    early_index: HashMap<DialogId, ExchangeKey>,
    /// The BYEs on their way to the core, by the usage they end. Each usage
    /// has one at most, so the usage table bounds them.
    byes: HashMap<UsageKey, SendingBye>,
    /// Why each of the last usages to end ended, the oldest first, so that a
    /// snapshot can say it after the notification was lost. At most
    /// `limits.usages` are kept.
    ended: VecDeque<(UsageKey, EndReason, Negotiation)>,
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
            early_index: HashMap::new(),
            byes: HashMap::new(),
            ended: VecDeque::new(),
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
                Command::Provisional { exchange, status, preview } => {
                    self.provisional(operation, exchange, status, preview)
                }
                Command::Invite { plan } => self.invite(operation, *plan),
                Command::Cancel { attempt } => {
                    self.cancel_attempt(Some(operation), attempt)
                }
                Command::Abandon { attempt } => {
                    let outcome = self
                        .abandon_attempt(attempt)
                        .map(|()| Completion::Done);
                    self.complete(operation, outcome);
                }
                Command::Terminate { usage } => {
                    self.terminate(Some(operation), usage);
                }
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

    /// Returns why a usage ended, and where its negotiation stood then, as
    /// long as it is among the last ones to end.
    pub(crate) fn ended(
        &self,
        usage: UsageKey,
    ) -> Option<(EndReason, Negotiation)> {
        self.ended
            .iter()
            .rev()
            .find(|(key, ..)| *key == usage)
            .map(|&(_, reason, negotiation)| (reason, negotiation))
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
    /// The checks follow the order of RFC 3261 section 8.2: the To tag and
    /// the Request-URI, a merged request, then Require, then the body
    /// (section 8.2.3). Then come the headers the dialog needs, and its
    /// Expires (section 13.3.1). `body` is what [`Body::read`] made of the
    /// request's body. A session description in it is the offer, and an
    /// INVITE without one gets an offer in its 2xx (section 13.2.1). The
    /// application's decision is due one decision timeout after `now`.
    pub(crate) fn receive_invite<B>(
        &mut self,
        request: &Request<B>,
        body: Result<Body, Malformed>,
        now: Instant,
    ) -> Result<Authority, Refusal> {
        match self.classify(request)? {
            Incoming::Initial => {}
            Incoming::NoDialog => return Err(Refusal::NoDialog),
            // A dialog this user agent sent a BYE in is Mortal, and a
            // re-INVITE in it gets a 481 (RFC 5407 section 3.2.2).
            Incoming::InDialog(dialog) if self.is_mortal(dialog) => {
                return Err(Refusal::NoDialog);
            }
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
        let offer = match body? {
            Body::Session(offer) => Some(offer),
            Body::Empty | Body::Other => None,
            Body::Unsupported => return Err(Refusal::UnsupportedBody),
        };

        if protocol::sips_on_the_way_back(headers)? {
            return Err(Refusal::SipsNotAllowed);
        }
        let expires = protocol::expires(headers)?;

        let Some(local_tag) = self.tag() else {
            return Err(Refusal::Internal);
        };
        let dialog = Dialog::uas(request, local_tag, self.limits.routes)?;
        let early = dialog.id().clone();
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
        self.early_index.insert(early, exchange);
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
    ///
    /// A preview of the answer goes only for an INVITE with an offer. RFC
    /// 3261 section 13.2.1 lets the answer come in a provisional response as
    /// well as in the 2xx. The offer of an INVITE without one goes in the 2xx
    /// instead, since an unreliable provisional cannot carry an offer whose
    /// answer is owed.
    fn provisional(
        &mut self,
        operation: OperationId,
        key: ExchangeKey,
        status: StatusCode,
        preview: Option<Description>,
    ) {
        let Some(exchange) = self.exchanges.get(key) else {
            self.complete(operation, Err(Error::StaleDecision));
            return;
        };
        if exchange.state() != ExchangeState::Pending {
            self.complete(operation, Err(Error::AlreadyFinalized));
            return;
        }
        let Scope::Incoming { dialog: Some(dialog), offer, .. } =
            &exchange.scope
        else {
            unreachable!("a pending incoming exchange keeps its dialog");
        };
        // A 100 is the core's to send (RFC 3261 section 17.2.1).
        if !(101..=199).contains(&status.as_u16())
            || (preview.is_some() && offer.is_none())
        {
            self.complete(operation, Err(Error::InvalidInput));
            return;
        }

        let to_tag = dialog.id().local_tag().clone();
        self.effects.push(Effect::SubmitProvisional {
            exchange: key,
            status,
            to_tag,
            preview,
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
        preview: Option<Description>,
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
        if let Some(last) = provisional.take() {
            self.timers.cancel(last.due, Timer::Provisional(key));
        }
        let due = now + PROVISIONAL_INTERVAL;
        *provisional = Some(Box::new(Provisional { status, preview, due }));
        self.timers.set(due, Timer::Provisional(key));
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
            provisional: Some(provisional),
            ..
        } = &mut exchange.scope
        else {
            return;
        };

        let next = after(at, PROVISIONAL_INTERVAL, now);
        provisional.due = next;
        self.timers.set(next, Timer::Provisional(key));
        self.effects.push(Effect::SubmitProvisional {
            exchange: key,
            status: provisional.status,
            to_tag: dialog.id().local_tag().clone(),
            preview: provisional.preview.clone(),
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
        if let Some(provisional) = provisional.take() {
            self.timers.cancel(provisional.due, Timer::Provisional(key));
        }
    }

    /// Removes an incoming exchange with its timers and its place in the
    /// merge index, and has the runtime let go of its responder.
    fn drop_exchange(&mut self, key: ExchangeKey) {
        self.stop_exchange_timers(key);
        let Some(exchange) = self.exchanges.remove(key) else {
            return;
        };

        if let Scope::Incoming { merge, dialog, .. } = &exchange.scope {
            if self.merge_index.get(merge) == Some(&key) {
                self.merge_index.remove(merge);
            }
            if let Some(dialog) = dialog {
                self.forget_early(dialog.id(), key);
            }
        }
        self.effects.push(Effect::Released(Released::Exchange(key)));
    }

    /// Takes an incoming exchange's early dialog out of the index, once a
    /// final decides the exchange and no BYE can withdraw it.
    fn forget_early(&mut self, id: &DialogId, key: ExchangeKey) {
        if self.early_index.get(id) == Some(&key) {
            self.early_index.remove(id);
        }
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
        let Scope::Incoming { dialog, offer, withdrawn, .. } =
            &mut exchange.scope
        else {
            unreachable!("only incoming exchanges submit finals");
        };
        let (offer, withdrawn) = (offer.take(), withdrawn.as_deref().copied());
        let offer_in_request = offer.is_some();
        let mut dialog = *dialog.take().expect("a 2xx forms the dialog once");
        // From here on the dialog is in the dialog table, which finds the
        // requests the caller sends in it.
        self.forget_early(dialog.id(), key);

        // The 2xx carries the answer to the INVITE's offer, or an offer of
        // its own whose answer comes in the ACK (RFC 3261 section 13.2.1).
        let mut negotiation = Negotiation::Stable;
        if offer_in_request {
            negotiation.offer_received(cseq).expect("stable");
            negotiation.answer_sent(cseq).expect("the offer is outstanding");
        } else {
            negotiation.offer_sent(cseq).expect("stable");
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
        if offer_in_request {
            self.effects
                .push(Effect::Notify(Event::NegotiationCompleted { usage }));
        }

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

        // The caller sent a BYE in the early dialog while the 2xx was on its
        // way, and the UA answered it with a 200. The 2xx confirmed the
        // dialog that BYE ends (RFC 5407 section 3.1.3), so the session ends
        // as it starts. The 2xx still goes out again until its ACK, as RFC
        // 3261 section 13.3.1.4 asks. A CANCEL has no effect on a final
        // already sent (section 9.2).
        if let Some(Withdrawal::Bye { flow }) = withdrawn {
            self.end_usage(usage, EndReason::RemoteBye { flow });
        }
    }

    /// Keeps an ACK for a 2xx whose submission the core has not confirmed
    /// yet, so that the race between the two does not lose it. An ACK that
    /// matches no 2xx in flight is dropped.
    fn hold_early_ack(
        &mut self,
        dialog: &DialogId,
        cseq: u32,
        answer: Option<Description>,
    ) {
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
            let held = exchange.early_ack.get_or_insert(None);
            if held.is_none() {
                *held = answer;
            }
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
            // The caller gave the INVITE up while the application's final
            // was on its way. The final lost, so the INVITE gets the 487 it
            // would have had then (RFC 3261 sections 9.2 and 15.1.2).
            if self.withdrawn(key).is_some() {
                self.answer_withdrawal(key);
            } else {
                self.abandon(key);
            }
        } else {
            // The UA's own final was refused. I do not retry it, since no
            // RFC rule asks for more than a final response, and signa-core
            // gives one. Dropping the exchange drops its responder, and
            // signa-core sends its 500 for an unanswered one.
            self.drop_exchange(key);
        }
    }

    /// Returns how the caller gave up an incoming INVITE, if it did.
    fn withdrawn(&self, key: ExchangeKey) -> Option<Withdrawal> {
        match &self.exchanges.get(key)?.scope {
            Scope::Incoming { withdrawn, .. } => withdrawn.as_deref().copied(),
            Scope::Outgoing => None,
        }
    }

    /// Takes in a CANCEL of the INVITE of an incoming exchange, which the
    /// core matched to the INVITE's transaction (RFC 3261 section 9.2).
    ///
    /// Returns the To tag of the INVITE's responses, which the 200 to the
    /// CANCEL SHOULD carry too (section 9.2), or `None` once the UA no
    /// longer holds the exchange. The 200 itself is the runtime's to send,
    /// whatever the INVITE's state, since the CANCEL matched a transaction.
    pub(crate) fn receive_cancel(&mut self, key: ExchangeKey) -> Option<Tag> {
        let exchange = self.exchanges.get(key)?;
        let tag = match &exchange.scope {
            Scope::Incoming { dialog: Some(dialog), .. } => {
                dialog.id().local_tag().clone()
            }
            // The 2xx went, and the dialog with it, so the tag is the
            // dialog's. The CANCEL changes nothing then.
            Scope::Incoming { dialog: None, .. } => {
                return self.committed_tag(key);
            }
            Scope::Outgoing => return None,
        };

        self.withdraw(key, Withdrawal::Cancel);
        Some(tag)
    }

    /// Takes in a request with a To tag other than INVITE, ACK and CANCEL,
    /// which arrived on `flow`, and says how to answer it.
    ///
    /// RFC 3261 section 12.2.2 finds its dialog by the tags and Call-ID, and
    /// checks its CSeq against the last one the peer sent. A BYE ends the
    /// session of its dialog and gets a 200 (section 15.1.2). So does a BYE
    /// in the early dialog of an INVITE this user agent has not answered,
    /// which also gets that INVITE a 487 (section 15.1.2, and RFC 5407
    /// appendix A). A request that changes nothing in the dialog is answered
    /// as one outside it. A dialog that matches none gets a 481.
    ///
    /// In a dialog that is Mortal, since this user agent sent a BYE in it, a
    /// BYE still gets a 200 and any other request a 481 ([RFC 5407 sections
    /// 2 and 3.2.1]). Nothing else changes, and the CSeq is not checked,
    /// since the dialog takes no new request.
    ///
    /// [RFC 5407 sections 2 and 3.2.1]: https://www.rfc-editor.org/rfc/rfc5407.html#section-3.2.1
    pub(crate) fn receive_request<B>(
        &mut self,
        request: &Request<B>,
        flow: Flow,
    ) -> Result<InDialog, Refusal> {
        let Some(id) = request_dialog(request)? else {
            return Ok(InDialog::Other);
        };
        let (cseq, _) = protocol::cseq(request.headers())?;
        let bye = *request.method() == Method::BYE;

        if let Some(&key) = self.dialog_index.get(&id) {
            if self.is_mortal(key) {
                return if bye {
                    Ok(InDialog::Bye)
                } else {
                    Err(Refusal::NoDialog)
                };
            }
            let dialog = self.dialogs.get_mut(key).expect("indexed");
            dialog.remote_request(cseq).map_err(out_of_order)?;
            if !bye {
                return Ok(InDialog::Other);
            }

            let usage = self
                .usages
                .iter()
                .find_map(|(usage, record)| {
                    (record.dialog == key).then_some(usage)
                })
                .expect("a live dialog has its usage");
            self.end_usage(usage, EndReason::RemoteBye { flow });
            return Ok(InDialog::Bye);
        }

        let Some(&key) = self.early_index.get(&id) else {
            return Err(Refusal::NoDialog);
        };
        let Some(InviteExchange {
            scope: Scope::Incoming { dialog: Some(dialog), .. },
            ..
        }) = self.exchanges.get_mut(key)
        else {
            unreachable!("an indexed early dialog is its exchange's");
        };
        dialog.remote_request(cseq).map_err(out_of_order)?;
        if bye {
            self.withdraw(key, Withdrawal::Bye { flow });
            return Ok(InDialog::Bye);
        }
        Ok(InDialog::Other)
    }

    /// Says whether a dialog is Mortal: this user agent ended its session
    /// with a BYE whose transaction has not ended yet.
    fn is_mortal(&self, dialog: DialogKey) -> bool {
        self.dialogs
            .get(dialog)
            .is_some_and(|dialog| dialog.phase() == DialogPhase::Terminated)
    }

    /// Returns the To tag of the 2xx an incoming exchange committed, from the
    /// replay context that awaits its ACK.
    fn committed_tag(&self, key: ExchangeKey) -> Option<Tag> {
        self.replays.iter().find_map(|(_, replay)| {
            (replay.source == Source::Exchange(key))
                .then(|| replay.id.dialog.local_tag().clone())
        })
    }

    /// Records that the caller gave up an incoming INVITE.
    ///
    /// An INVITE still undecided gets a 487 at once (RFC 3261 section 9.2
    /// for a CANCEL, section 15.1.2 for a BYE in its early dialog). One whose
    /// final is under way keeps it, and the withdrawal applies only if the
    /// core refuses that final. One that has its final already is left
    /// alone, since neither request undoes it (section 9.2).
    fn withdraw(&mut self, key: ExchangeKey, withdrawal: Withdrawal) {
        let Some(exchange) = self.exchanges.get_mut(key) else {
            return;
        };
        let state = exchange.state();
        let Scope::Incoming { withdrawn, .. } = &mut exchange.scope else {
            return;
        };
        if !matches!(
            state,
            ExchangeState::Pending
                | ExchangeState::FinalSubmissionPending { .. }
        ) {
            return;
        }
        // The first one counts. A BYE after a CANCEL still answers a 2xx in
        // flight with the end of its session, though.
        if withdrawn.is_none() || matches!(withdrawal, Withdrawal::Bye { .. })
        {
            *withdrawn = Some(Box::new(withdrawal));
        }

        if state == ExchangeState::Pending {
            self.answer_withdrawal(key);
        }
    }

    /// Answers an INVITE the caller gave up with a 487, and tells the
    /// application, whose decision now finds the final taken.
    fn answer_withdrawal(&mut self, key: ExchangeKey) {
        let terminated = StatusCode::from_u16(487).expect("a final status");
        self.reject(key, terminated);
        self.effects
            .push(Effect::Notify(Event::InviteWithdrawn { exchange: key }));
    }

    /// Takes in an ACK as received, with the session description it
    /// carries, if any. An ACK without the dialog headers is dropped. Nothing
    /// answers an ACK, since the ACK of a 2xx goes outside any transaction
    /// (RFC 3261 section 13.2.2.4).
    pub(crate) fn receive_ack_request<B>(
        &mut self,
        request: &Request<B>,
        answer: Option<Description>,
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
    ///
    /// What the body says is a second step. When the 2xx carried an offer,
    /// the ACK owes the answer (section 13.2.1). An answer completes the
    /// exchange, and the session keeps it for the application, whose SDP
    /// component judges it. The UA does not. An ACK without one fails the
    /// exchange, which the UA cannot repair, since the ACK takes no response.
    /// The session then ends with a BYE, my policy for a session whose
    /// descriptions never settled. An ACK for a 2xx that carried the answer
    /// owes nothing, and a description in it is ignored.
    pub(crate) fn receive_ack(
        &mut self,
        dialog: &DialogId,
        cseq: u32,
        answer: Option<Description>,
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
            let mut failed = false;
            if record.negotiation.awaits_answer(cseq) {
                match answer {
                    Some(answer) => {
                        record
                            .negotiation
                            .answer_received(cseq)
                            .expect("checked to await it");
                        record.remote = Some(answer);
                        self.effects.push(Effect::Notify(
                            Event::NegotiationCompleted { usage },
                        ));
                    }
                    None => {
                        failed = true;
                        self.effects.push(Effect::Notify(
                            Event::NegotiationFailed { usage },
                        ));
                    }
                }
            }
            // The application asked to end the session before the ACK, and
            // RFC 3261 section 15 lets its BYE go now.
            match record.bye {
                ByeIntent::Deferred { operation, reason } => {
                    let restore = reason == EndReason::LocalBye;
                    self.start_bye(usage, operation, reason, restore);
                }
                ByeIntent::None if failed => {
                    let reason = EndReason::NegotiationFailed;
                    self.start_bye(usage, None, reason, false);
                }
                ByeIntent::None | ByeIntent::Sending => {}
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
    /// session end with a BYE, which section 15 allows now that the wait for
    /// the ACK is over. The usage ends once the BYE reaches the core, or
    /// without it if it cannot. A BYE the application asked for goes now, as
    /// its own. A late ACK finds nothing afterwards, so it brings back
    /// neither the usage nor the retransmissions.
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
        if let Some((usage, bye)) =
            usage.and_then(|usage| Some((usage, self.usages.get(usage)?.bye)))
        {
            self.effects.push(Effect::Notify(Event::AckTimeout { usage }));
            match bye {
                ByeIntent::None => {
                    self.start_bye(usage, None, EndReason::AckTimeout, false);
                }
                ByeIntent::Deferred { operation, reason } => {
                    self.start_bye(usage, operation, reason, false);
                }
                ByeIntent::Sending => {}
            }
        }
        self.reclaim_replay(key);
    }
}

/// Refuses a request out of order in its dialog, whether its CSeq is lower
/// than the last or the same.
fn out_of_order(_: OutOfOrder) -> Refusal {
    Refusal::OutOfOrder
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
        let attempt =
            match self.start_attempt(&planned.request, plan.has_offer()) {
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

    /// Records that the core took the INVITE of an attempt, and asks it for
    /// the CANCEL the application wanted before then.
    pub(crate) fn invite_started(&mut self, attempt: AttemptKey) {
        let Some(record) = self.attempts.get_mut(attempt) else {
            return;
        };
        let Some(operation) = record.operation.take() else {
            return;
        };

        if let CancelIntent::Waiting(cancel) = record.cancel {
            record.cancel = CancelIntent::Asked;
            self.effects
                .push(Effect::CancelInvite { attempt, operation: cancel });
        }
        self.operations.advance(operation, Stage::Committed);
        self.complete(operation, Ok(Completion::Attempt(attempt)));
    }

    /// Records that the INVITE of an attempt never reached the core, and
    /// closes the attempt. A CANCEL asked for meanwhile is not needed.
    pub(crate) fn invite_failed(&mut self, attempt: AttemptKey, error: Error) {
        let Some(record) = self.attempts.remove(attempt) else {
            return;
        };

        self.exchanges.remove(record.exchange);
        self.effects.push(Effect::Released(Released::Attempt(attempt)));
        if let Some(operation) = record.operation {
            self.complete(operation, Err(error));
        }
        if let CancelIntent::Waiting(Some(cancel)) = record.cancel {
            let not_needed = Completion::Cancel(CancelResult::NotNeeded);
            self.complete(cancel, Ok(not_needed));
        }
    }

    /// Asks for the CANCEL of an attempt's INVITE, for `operation` if the
    /// application asked.
    ///
    /// The core sends the CANCEL once a provisional response came, and none
    /// if a final came first (RFC 3261 section 9.1). Before the core has the
    /// INVITE, the intent waits for it. An INVITE that already has its final
    /// gets no CANCEL, since it would do nothing (section 9.1 says it SHOULD
    /// NOT go). The CANCEL decides nothing about the attempt. A 2xx that
    /// wins the race forms a session as any other, which the application
    /// may keep or end (section 15).
    fn cancel_attempt(
        &mut self,
        operation: Option<OperationId>,
        attempt: AttemptKey,
    ) {
        let Some(record) = self.attempts.get_mut(attempt) else {
            if let Some(operation) = operation {
                self.complete(operation, Err(Error::StaleDecision));
            }
            return;
        };
        if record.cancel != CancelIntent::None {
            if let Some(operation) = operation {
                self.complete(operation, Err(Error::InvalidTransition));
            }
            return;
        }
        if record.result.is_some() {
            if let Some(operation) = operation {
                let not_needed = Completion::Cancel(CancelResult::NotNeeded);
                self.complete(operation, Ok(not_needed));
            }
            return;
        }

        if record.started() {
            record.cancel = CancelIntent::Asked;
            self.effects.push(Effect::CancelInvite { attempt, operation });
        } else {
            record.cancel = CancelIntent::Waiting(operation);
        }
    }

    /// Records what the core did with a CANCEL it was asked for.
    pub(crate) fn cancel_done(
        &mut self,
        operation: Option<OperationId>,
        result: Result<CancelResult, Error>,
    ) {
        let Some(operation) = operation else {
            return;
        };

        if result == Ok(CancelResult::Sent) {
            self.operations.advance(operation, Stage::Committed);
        }
        self.complete(operation, result.map(Completion::Cancel));
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

    /// Gives an attempt up, as the application intends, which is what RFC
    /// 3261 section 15 describes for a caller that hangs up: a CANCEL while
    /// the INVITE has no final response, and a BYE in each confirmed dialog.
    ///
    /// * The INVITE gets its CANCEL, unless it has its final already.
    /// * Each session it formed that is confirmed gets its BYE.
    /// * An early session is left to the CANCEL, whose 487 ends it, and
    ///   shows as ending meanwhile.
    /// * Each 2xx that comes from now on, also one for an early dialog, gets
    ///   its ACK and a BYE that ends its dialog, and forms no session
    ///   (section 13.2.2.4).
    ///
    /// Giving up twice does no more than once. A session that is already
    /// ending keeps its BYE. A BYE that cannot reach the core leaves its
    /// session up, for the application to end again, since the peer still
    /// has it.
    pub(crate) fn abandon_attempt(
        &mut self,
        attempt: AttemptKey,
    ) -> Result<(), Error> {
        let record =
            self.attempts.get_mut(attempt).ok_or(Error::StaleDecision)?;
        record.abandoned = true;
        let forks = record.forks.clone();

        self.cancel_attempt(None, attempt);
        for usage in forks {
            let Some(record) = self.usages.get_mut(usage) else {
                continue;
            };
            match record.phase() {
                UsagePhase::Established => self.bye_when_ready(usage, None),
                UsagePhase::Establishing => record.begin_ending(),
                UsagePhase::Ending | UsagePhase::Ended => {}
            }
        }
        Ok(())
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

    /// Ends the early usages an attempt formed, also those ending, whose
    /// dialog no 2xx can confirm any more.
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
                    self.dialogs.get(usage.dialog).map(Dialog::phase)
                        == Some(DialogPhase::Early)
                })
            })
            .collect();

        for usage in early {
            self.end_usage(usage, EndReason::Unconfirmed);
        }
    }

    /// Says whether the model still keeps a replay context.
    #[cfg(test)]
    pub(crate) fn has_replay(&self, replay: ReplayKey) -> bool {
        self.replays.get(replay).is_some()
    }

    /// Builds the ACK of the 2xx a replay context is for, from its dialog
    /// (RFC 3261 section 13.2.2.4), with the answer it carries, if any. A
    /// cleanup builds it from the dialog it holds, which no table does.
    pub(crate) fn ack_request(
        &mut self,
        replay: ReplayKey,
    ) -> Option<(Outgoing, Option<Description>)> {
        let context = self.replays.get_mut(replay)?;
        let cseq = context.id.cseq;
        let answer = match &context.ack_body {
            AckBody::Answer(answer) => Some(answer.clone()),
            AckBody::Empty | AckBody::Unanswered => None,
            AckBody::Preparing => return None,
        };
        if let Some(dialog) = &mut context.dialog {
            let ack = dialog.request(Method::ACK, Sequence::Of(cseq)).ok()?;
            return Some((ack, answer));
        }
        let dialog = *self.dialog_index.get(&context.id.dialog)?;

        let ack = self
            .dialogs
            .get_mut(dialog)?
            .request(Method::ACK, Sequence::Of(cseq))
            .ok()?;
        Some((ack, answer))
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
    /// A session description in the response is a preview, which the early
    /// session keeps for the application, as early media may need it. For an
    /// INVITE with an offer it is the answer, since RFC 3261 section 13.2.1
    /// has the UAC take the first session description it receives as one.
    /// It completes nothing, though. The response is unreliable, and the 2xx
    /// has to carry the answer or offer all the same (RFC 6337 section
    /// 3.1.1). The first preview of a dialog is kept, from whichever
    /// provisional brings one, and later ones are ignored.
    ///
    /// [RFC 6141 section 4.9]: https://www.rfc-editor.org/rfc/rfc6141.html#section-4.9
    pub(crate) fn receive_provisional<B>(
        &mut self,
        key: AttemptKey,
        response: &Response<B>,
        preview: Option<Description>,
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
        // A later provisional for an early dialog formed before may bring
        // its first preview.
        if let Some(&dialog) = self.dialog_index.get(&id) {
            let early = attempt.forks.iter().find_map(|&usage| {
                let record = self.usages.get(usage)?;
                (record.dialog == dialog
                    && record.phase() == UsagePhase::Establishing)
                    .then_some(usage)
            });
            if let Some(usage) = early {
                let record = self.usages.get_mut(usage).expect("found");
                record.remote = record.remote.take().or(preview);
            }
            return Ok(());
        }
        // Nor does one for a dialog this user agent ended with a BYE.
        if attempt.abandoned
            || self.replay_index.contains_key(&answered)
            || attempt.ended_early(&id).is_some()
        {
            return Ok(());
        }

        let dialog =
            Dialog::uac(&attempt.origin, response, self.limits.routes)
                .map_err(|_| Error::InvalidInput)?;
        let negotiation = if attempt.offer_in_request {
            Negotiation::LocalOfferOutstanding { cseq: attempt.origin.cseq() }
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
        let mut record =
            InviteUsage::early(dialog, Direction::Outgoing, negotiation);
        record.remote = preview;
        let usage = self.usages.insert_reserved(record);
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
        // of a cleanup, gets the ACK again, and neither a new session, nor a
        // second answer, nor a second BYE. While the answer is prepared there
        // is no ACK yet, and the copy gets the one that goes then.
        if let Some(&replay) = self.replay_index.get(&replay) {
            let context = self.replays.get(replay).expect("indexed");
            if context.ack_body != AckBody::Preparing {
                self.effects.push(Effect::ResendAck { replay });
            }
            return Ok(());
        }
        let known = self.dialog_index.get(&id).copied();
        if let Some(numbered) = attempt.ended_early(&id) {
            // This user agent ended the early dialog with a BYE, which
            // crossed the 2xx, whether or not the BYE's transaction is still
            // on. RFC 5407 appendix A has a UAC ready for a 2xx until the
            // INVITE's final, and section 13.2.2.4 of RFC 3261 asks for its
            // ACK and a BYE all the same. The dialog's numbers go on from the
            // BYE's, which the peer may have seen. Ending it was the
            // application's choice, so the attempt stays complete.
            let mut dialog =
                Dialog::uac(&attempt.origin, response, self.limits.routes)
                    .map_err(|_| Error::InvalidInput)?;
            dialog.number_after(numbered);
            return self
                .clean_up(key, dialog, replay, description)
                .then_some(())
                .ok_or(Error::CapacityExceeded);
        }
        if let Some(dialog) = known {
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
                .clean_up(key, dialog, replay, description)
                .then_some(())
                .ok_or(Error::CapacityExceeded);
        }
        if forks >= self.limits.forks || !self.reserve_session() {
            self.clean_up(key, dialog, replay, description);
            return Err(Error::CapacityExceeded);
        }

        // Each fork starts from the INVITE's offer and goes on alone, since
        // each answer, or offer, comes from another peer.
        let cseq = replay.cseq;
        let negotiation = if offer_in_request {
            Negotiation::LocalOfferOutstanding { cseq }
        } else {
            Negotiation::Stable
        };
        let (replay, usage) = self.establish(
            dialog,
            Direction::Outgoing,
            negotiation,
            replay,
            Source::Attempt(key),
        );
        self.attempts.get_mut(key).expect("checked above").forks.push(usage);
        self.settle_2xx(usage, replay, cseq, description);
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
            self.end_usage(usage, EndReason::LocalBye);
            let cleaned = self.clean_up(attempt, record, replay, description);
            debug_assert!(cleaned, "the room was checked above");
            return if abandoned {
                Ok(())
            } else {
                Err(Error::CapacityExceeded)
            };
        }

        self.usages.get_mut(usage).expect("found above").establish();
        let cseq = replay.cseq;
        let context = ReplayContext::new(
            replay.clone(),
            Source::Attempt(attempt),
            usage,
        );
        let key = self.replays.insert_reserved(context);
        self.replay_index.insert(replay, key);

        self.effects
            .push(Effect::Notify(Event::DialogConfirmed { dialog, usage }));
        self.settle_2xx(usage, key, cseq, description);
        Ok(())
    }

    /// Moves a session's negotiation past the 2xx that confirmed it, and has
    /// the ACK go now, or once the answer it owes is in.
    ///
    /// The 2xx carries the answer to the INVITE's offer, or an offer when the
    /// INVITE had none, whose answer the ACK owes (RFC 3261 section 13.2.1).
    /// That answer comes from outside, through [`Effect::PrepareAnswer`],
    /// and the ACK waits for it. A 2xx without what it owes fails the
    /// exchange. It is acknowledged all the same (section 13.2.2.4), and the
    /// session ends with a BYE after the ACK, my policy for a session whose
    /// descriptions never settled.
    ///
    /// When a provisional response previewed the answer, the preview stays
    /// the answer. RFC 3261 section 13.2.1 has the UAC take the first session
    /// description it receives as the answer and ignore later ones, and RFC
    /// 6337 section 3.1.1 keeps it even when the 2xx carries another. The 2xx
    /// still has to carry one, since only it is reliable, and a 2xx whose
    /// description differs is reported. Neither rule applies to the offer of
    /// an INVITE without one, which is the 2xx's own.
    fn settle_2xx(
        &mut self,
        usage: UsageKey,
        replay: ReplayKey,
        cseq: u32,
        description: Option<Description>,
    ) {
        let record = self.usages.get_mut(usage).expect("a session just made");

        match (record.negotiation, description) {
            (Negotiation::LocalOfferOutstanding { .. }, Some(answer)) => {
                record
                    .negotiation
                    .answer_received(cseq)
                    .expect("the INVITE's offer is outstanding");
                match &record.remote {
                    Some(preview) if *preview != answer => {
                        self.effects.push(Effect::Notify(
                            Event::AnswerChanged { usage },
                        ));
                    }
                    Some(_) => {}
                    None => record.remote = Some(answer),
                }
                self.effects.push(Effect::Notify(
                    Event::NegotiationCompleted { usage },
                ));
                self.effects.push(Effect::SendAck { replay });
            }
            (Negotiation::Stable, Some(offer)) => {
                record.negotiation.offer_received(cseq).expect("stable");
                record.remote = Some(offer.clone());
                let context = self.replays.get_mut(replay).expect("just made");
                context.ack_body = AckBody::Preparing;
                self.effects.push(Effect::PrepareAnswer {
                    replay,
                    offer,
                    usage: Some(usage),
                });
            }
            _ => {
                self.fail_negotiation(usage);
                self.effects.push(Effect::SendAck { replay });
            }
        }
    }

    /// Reports the failed exchange of a session that sent an INVITE, and
    /// has it end with a BYE once its ACK has gone, unless a BYE is asked
    /// for already.
    fn fail_negotiation(&mut self, usage: UsageKey) {
        let Some(record) = self.usages.get_mut(usage) else {
            return;
        };

        if record.bye == ByeIntent::None {
            record.begin_ending();
            record.bye = ByeIntent::Deferred {
                operation: None,
                reason: EndReason::NegotiationFailed,
            };
        }
        self.effects.push(Effect::Notify(Event::NegotiationFailed { usage }));
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
    /// The 2xx of an INVITE without an offer carries one, and its ACK owes
    /// the answer even for a dialog the UAC ends (section 13.2.1). The ACK
    /// waits for an answer that rejects the offer, which the
    /// [`Effect::PrepareAnswer`] without a usage asks for.
    fn clean_up(
        &mut self,
        attempt: AttemptKey,
        dialog: Dialog,
        replay: ReplayId,
        description: Option<Description>,
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
        let late = self
            .attempts
            .get(attempt)
            .is_some_and(|record| !record.offer_in_request);
        match description.filter(|_| late) {
            Some(offer) => {
                let context = self.replays.get_mut(key).expect("just made");
                context.ack_body = AckBody::Preparing;
                self.effects.push(Effect::PrepareAnswer {
                    replay: key,
                    offer,
                    usage: None,
                });
            }
            None => self.effects.push(Effect::SendAck { replay: key }),
        }
        true
    }

    /// Takes in the answer prepared for the ACK of a 2xx that carried an
    /// offer, or `None` when none could be had in time.
    ///
    /// The answer goes in the ACK, and in every copy of it, so the exchange
    /// is complete. An answer for a context that is gone, or that already
    /// has its answer, is stale and changes nothing. A context's key names
    /// its slot and the generation of the slot, so an answer for a reclaimed
    /// context never reaches a new one in the same slot.
    ///
    /// Without an answer the exchange fails. The ACK goes without one
    /// anyway, to stop the 2xx's retransmissions, and the dialog ends with a
    /// BYE after it. Neither is a completed exchange, and RFC 3261 section
    /// 13.2.1 is not met, so the attempt reports itself degraded, and a
    /// session the failure ends says why.
    pub(crate) fn answer_prepared(
        &mut self,
        key: ReplayKey,
        answer: Option<Description>,
    ) {
        let Some(context) = self.replays.get_mut(key) else {
            return;
        };
        if context.ack_body != AckBody::Preparing {
            return;
        }

        let (usage, source, cseq) =
            (context.usage, context.source, context.id.cseq);
        let answered = answer.is_some();
        context.ack_body = match answer {
            Some(answer) => AckBody::Answer(answer),
            None => AckBody::Unanswered,
        };
        let attempt = match source {
            Source::Attempt(attempt) => self.attempts.get_mut(attempt),
            Source::Exchange(_) => None,
        };
        if let (false, Some(record)) = (answered, attempt) {
            record.degraded = true;
        }

        if let Some(usage) =
            usage.filter(|&usage| self.usages.get(usage).is_some())
        {
            if answered {
                let record = self.usages.get_mut(usage).expect("checked");
                if record.negotiation.answer_sent(cseq).is_ok() {
                    self.effects.push(Effect::Notify(
                        Event::NegotiationCompleted { usage },
                    ));
                }
            } else {
                self.fail_negotiation(usage);
            }
        }
        self.effects.push(Effect::SendAck { replay: key });
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

        // A BYE that waited for this ACK, since the ACK had an answer to
        // carry, or the exchange failed, goes now.
        let deferred =
            replay.usage.and_then(|usage| match self.usages.get(usage)?.bye {
                ByeIntent::Deferred { operation, reason } => {
                    Some((usage, operation, reason))
                }
                ByeIntent::None | ByeIntent::Sending => None,
            });
        if let Some((usage, operation, reason)) = deferred {
            let restore = reason == EndReason::LocalBye;
            self.start_bye(usage, operation, reason, restore);
        }
        self.reclaim_replay(key);
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

/// Usages.
impl<R: Random> Model<R> {
    /// Ends a usage, as when the peer's BYE is accepted or its early dialog
    /// ends without a 2xx. The dialog ends with it. The replay contexts of
    /// its 2xx stay until copies of the 2xx can no longer arrive.
    pub(crate) fn end_usage(&mut self, key: UsageKey, reason: EndReason) {
        self.finish_usage(key, reason, false);
    }

    /// Ends a usage whose BYE the core took, as [`Model::end_usage`] does,
    /// but leaves its dialog Mortal until the BYE's transaction ends
    /// ([RFC 5407 section 2]), for [`Model::bye_answered`] to reclaim.
    ///
    /// [RFC 5407 section 2]: https://www.rfc-editor.org/rfc/rfc5407.html#section-2
    fn end_usage_mortal(&mut self, key: UsageKey, reason: EndReason) {
        self.finish_usage(key, reason, true);
    }

    fn finish_usage(
        &mut self,
        key: UsageKey,
        reason: EndReason,
        mortal: bool,
    ) {
        let Some(mut usage) = self.usages.remove(key) else {
            return;
        };
        usage.end();

        if mortal {
            if let Some(dialog) = self.dialogs.get_mut(usage.dialog) {
                dialog.terminate();
            }
        } else if let Some(mut dialog) = self.dialogs.remove(usage.dialog) {
            self.dialog_index.remove(dialog.id());
            // An ACK that waits for its answer is owed all the same, and is
            // built from the dialog once the answer is in, so the dialog
            // goes to it, as to a cleanup.
            let waiting = self.replays.iter_mut().find(|(_, replay)| {
                replay.usage == Some(key)
                    && replay.ack_body == AckBody::Preparing
            });
            match waiting {
                Some((_, replay)) => replay.dialog = Some(Box::new(dialog)),
                None => dialog.terminate(),
            }
        }
        // A BYE the application asked for, deferred until the ACK, is not
        // needed any more. The session ended as it asked, as when the peer's
        // BYE crossed it, so the operation succeeds with nothing sent.
        if let ByeIntent::Deferred { operation: Some(operation), .. } =
            usage.bye
        {
            self.complete(operation, Ok(Completion::Done));
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

        if self.ended.len() >= self.limits.usages {
            self.ended.pop_front();
        }
        self.ended.push_back((key, reason, usage.negotiation));
        self.effects
            .push(Effect::Notify(Event::UsageEnded { usage: key, reason }));
    }

    /// Ends a usage with a BYE, for `operation` if the application asked.
    ///
    /// RFC 3261 section 15 lets the caller send a BYE in an early or a
    /// confirmed dialog, and the callee in a confirmed one, once the ACK of
    /// its 2xx came or its wait for that ACK is over. A callee's usage
    /// therefore waits for that ACK with its BYE deferred. A usage that is
    /// already ending, or has ended, takes no second BYE.
    fn terminate(&mut self, operation: Option<OperationId>, key: UsageKey) {
        let Some(usage) = self.usages.get_mut(key) else {
            if let Some(operation) = operation {
                let error = if self.ended(key).is_some() {
                    Error::InvalidTransition
                } else {
                    Error::StaleDecision
                };
                self.complete(operation, Err(error));
            }
            return;
        };
        if usage.bye != ByeIntent::None {
            if let Some(operation) = operation {
                self.complete(operation, Err(Error::InvalidTransition));
            }
            return;
        }

        self.bye_when_ready(key, operation);
    }

    /// Has the BYE of a usage that has none go, or wait for an ACK: the
    /// peer's ACK of this user agent's 2xx, which RFC 3261 section 15 has a
    /// callee wait for, or this user agent's own ACK while it waits for the
    /// answer it carries, so that the BYE does not overtake it.
    fn bye_when_ready(
        &mut self,
        key: UsageKey,
        operation: Option<OperationId>,
    ) {
        // A UAS keeps a usage only once its 2xx is committed, so only an ACK
        // still awaited holds the BYE back.
        let awaiting_ack = self.replays.iter().any(|(_, replay)| {
            replay.usage == Some(key)
                && (replay.ack == AckObligation::AwaitingPeer
                    || replay.ack_body == AckBody::Preparing)
        });
        let Some(usage) = self.usages.get_mut(key) else {
            return;
        };
        if awaiting_ack {
            usage.begin_ending();
            usage.bye =
                ByeIntent::Deferred { operation, reason: EndReason::LocalBye };
            return;
        }

        self.start_bye(key, operation, EndReason::LocalBye, true);
    }

    /// Has the runtime send the BYE of a usage, which ends it once the core
    /// takes it (RFC 3261 section 15.1.1). If the core never does, the usage
    /// goes back to what it was if `restore`, or ends anyway without it.
    fn start_bye(
        &mut self,
        key: UsageKey,
        operation: Option<OperationId>,
        reason: EndReason,
        restore: bool,
    ) {
        let Some(usage) = self.usages.get_mut(key) else {
            return;
        };
        debug_assert_ne!(usage.bye, ByeIntent::Sending);

        usage.begin_ending();
        usage.bye = ByeIntent::Sending;
        let dialog = usage.dialog;
        self.byes
            .insert(key, SendingBye { operation, dialog, reason, restore });
        self.effects.push(Effect::SendSessionBye { usage: key });
    }

    /// Builds the BYE of a usage from its dialog, as any request in a dialog
    /// is built (RFC 3261 section 15.1.1). It takes the dialog's next number
    /// for good, sent or not, since it may reach the peer (section 8.1.1.5).
    pub(crate) fn session_bye_request(
        &mut self,
        key: UsageKey,
    ) -> Result<Outgoing, Error> {
        let dialog = self.byes.get(&key).ok_or(Error::StaleDecision)?.dialog;
        // A UAS that sent nothing in the dialog yet picks its first number
        // from this.
        let seed = self.random.next_u64().ok_or(Error::Internal)?;

        let record =
            self.dialogs.get_mut(dialog).ok_or(Error::StaleDecision)?;
        record.request(Method::BYE, Sequence::Next { seed }).map_err(|error| {
            match error {
                RequestError::Terminated => Error::StaleDecision,
                // Out of numbers, the dialog can take no new request.
                RequestError::CSeqExhausted => Error::InvalidTransition,
                RequestError::WrongSequence
                | RequestError::Cancel
                | RequestError::Invalid => Error::Internal,
            }
        })
    }

    /// Records whether the core took the BYE of a usage.
    ///
    /// Once it did, the session is over (RFC 3261 section 15.1.1), whatever
    /// the response says, and the dialog stays Mortal until the BYE's
    /// transaction ends. The returned [`ByeStarted`] is what the runtime
    /// reports that response with. A BYE that never reached the core leaves
    /// the usage as it was before, unless it was to end it anyway, as at an
    /// ACK timeout, where RFC 3261 section 13.3.1.4 ends the session either
    /// way.
    ///
    /// A usage the peer's BYE ended meanwhile stays ended. Its dialog went
    /// then, so nothing stays Mortal.
    pub(crate) fn bye_started(
        &mut self,
        key: UsageKey,
        result: Result<(), Error>,
    ) -> Option<ByeStarted> {
        let bye = self.byes.remove(&key)?;

        match result {
            Ok(()) => {
                if let Some(operation) = bye.operation {
                    self.operations.advance(operation, Stage::Committed);
                }
                self.remember_ended_early(key, bye.dialog);
                self.end_usage_mortal(key, bye.reason);
                Some(ByeStarted {
                    dialog: bye.dialog,
                    operation: bye.operation,
                })
            }
            Err(error) => {
                // A 2xx may have confirmed an early dialog meanwhile, so the
                // usage takes the phase its dialog says.
                let early = self.dialogs.get(bye.dialog).map(Dialog::phase)
                    == Some(DialogPhase::Early);
                let phase = if early {
                    UsagePhase::Establishing
                } else {
                    UsagePhase::Established
                };
                match (self.usages.get_mut(key), bye.restore) {
                    (Some(usage), true) => usage.resume(phase),
                    (Some(_), false) => self.end_usage(key, bye.reason),
                    (None, _) => {}
                }
                if let Some(operation) = bye.operation {
                    self.complete(operation, Err(error));
                }
                None
            }
        }
    }

    /// Has the attempt that formed an early dialog remember that this user
    /// agent ended it with a BYE, for as long as its 2xx may still come.
    fn remember_ended_early(&mut self, usage: UsageKey, dialog: DialogKey) {
        let Some(record) = self
            .dialogs
            .get(dialog)
            .filter(|record| record.phase() == DialogPhase::Early)
        else {
            return;
        };
        let ended = (record.id().clone(), record.local_cseq());
        let attempt = self
            .attempts
            .iter_mut()
            .find(|(_, attempt)| attempt.forks.contains(&usage));

        if let Some((_, attempt)) = attempt {
            attempt.ended_early.push(ended);
        }
    }

    /// Records the response to a BYE the core took, or the failure of its
    /// transaction, which ends the Mortal state of its dialog.
    ///
    /// The operation that asked for the BYE ends with it. A 481 or a timeout
    /// fails it, but brings back nothing (RFC 3261 section 15.1.1 takes the
    /// dialog as ended then too), and the BYE is not sent again.
    pub(crate) fn bye_answered(
        &mut self,
        bye: ByeStarted,
        result: Result<(), Error>,
    ) {
        if let Some(operation) = bye.operation {
            if matches!(result, Ok(()) | Err(Error::RemoteFailure(_))) {
                self.operations.advance(operation, Stage::Answered);
            }
            self.complete(operation, result.map(|()| Completion::Done));
        }

        if self.is_mortal(bye.dialog) {
            let dialog = self.dialogs.remove(bye.dialog).expect("checked");
            if self.dialog_index.get(dialog.id()) == Some(&bye.dialog) {
                self.dialog_index.remove(dialog.id());
            }
        }
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

    /// The body of an INVITE with an offer, which the model passes on
    /// without reading.
    fn offer() -> Result<Body, Malformed> {
        Ok(Body::Session(answer()))
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
                assert!(attempt.ended_early.len() <= attempt.forks.len());
            }

            for (key, usage) in self.usages.iter() {
                let dialog = self.dialogs.get(usage.dialog).unwrap();
                assert_ne!(dialog.phase(), DialogPhase::Terminated);
                assert_ne!(usage.phase(), UsagePhase::Ended);
                assert_eq!(
                    usage.bye == ByeIntent::Sending,
                    self.byes.contains_key(&key),
                );
                if usage.bye != ByeIntent::None {
                    assert_eq!(usage.phase(), UsagePhase::Ending);
                }
            }
            // A dialog no usage holds is Mortal, and waits for its BYE.
            let mortal = self
                .dialogs
                .iter()
                .filter(|(_, dialog)| {
                    dialog.phase() == DialogPhase::Terminated
                })
                .count();
            assert_eq!(self.dialogs.len(), self.usages.len() + mortal);
            for (_, dialog) in self.dialogs.iter() {
                assert!(self.dialog_index.contains_key(dialog.id()));
            }
            assert_eq!(self.dialog_index.len(), self.dialogs.len());
            assert!(self.ended.len() <= self.limits.usages);
            for (id, &key) in &self.early_index {
                let Some(InviteExchange {
                    scope: Scope::Incoming { dialog: Some(dialog), .. },
                    ..
                }) = self.exchanges.get(key)
                else {
                    panic!("an early dialog without its exchange");
                };
                assert_eq!(dialog.id(), id);
            }

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
        let authority = model
            .receive_invite(&request(INVITE), Ok(Body::Empty), clock.now())
            .unwrap();
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
            Negotiation::LocalOfferOutstanding { cseq: 314159 },
        );
        assert!(!negotiated(&effects));

        model.receive_ack(&id, 314159, Some(answer()));
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

        model.end_usage(usage, EndReason::LocalBye);
        model.check();
        assert_eq!(
            model.take_effects(),
            [Effect::Notify(Event::UsageEnded {
                usage,
                reason: EndReason::LocalBye
            })],
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

        model.receive_ack(&id, 314160, None);
        model.receive_ack(&swapped, 314159, None);
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
            .receive_provisional(attempt, &ringing("sip:bob@192.0.2.4"), None)
            .unwrap();
        let (dialog, usage) = match model.take_effects()[..] {
            [Effect::Notify(Event::EarlyDialog { dialog, usage })] => {
                (dialog, usage)
            }
            ref other => panic!("no early dialog: {other:?}"),
        };
        model
            .receive_provisional(attempt, &ringing("sip:bob@192.0.2.5"), None)
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
                None,
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
        model.receive_provisional(attempt, &ringing, None).unwrap();
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
                Event::UsageEnded { usage, reason: EndReason::Unconfirmed },
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

        let ack = model.ack_request(replay).unwrap().0;

        assert_eq!(ack.request.method(), &Method::ACK);
        assert_eq!(ack.request.uri().as_str(), "sip:bob@192.0.2.4");
        assert_eq!(ack.request.headers().get("CSeq").unwrap(), "314159 ACK");
    }

    /// An ACK as received finds its 2xx by the dialog and CSeq it carries.
    #[test]
    fn a_received_ack_finds_its_2xx() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), Ok(Body::Empty), clock.now())
            .unwrap();
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

        model.receive_ack_request(&request(&ack), Some(answer()));
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
        model.end_usage(usage, EndReason::LocalBye);
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
        model.receive_ack(&uas_dialog(), 314160, None);
        model.receive_ack(&uas_dialog(), 314159, None);
        model.receive_ack(&uas_dialog(), 314159, None);
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
        let authority = model
            .receive_invite(&request(INVITE), Ok(Body::Empty), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        model
            .try_submit(Command::Accept { authority, answer: answer() })
            .unwrap();
        model.run_commands();
        model.take_effects();

        model.receive_ack(&uas_dialog(), 314159, Some(answer()));
        model.receive_ack(&uas_dialog(), 314159, None);
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
    /// application is told why, and the session ends with a BYE, as RFC
    /// 3261 section 13.3.1.4 asks. The usage ends once the core has the BYE,
    /// and its dialog stays Mortal until the BYE's response. Nothing of the
    /// exchange is left. A BYE that cannot reach the core ends the session
    /// all the same.
    #[test]
    fn no_ack_triggers_explicit_termination_policy() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let (exchange, replay, usage) = accepted(&mut model, &clock);
        let deadline = clock.now() + T1 * 64;

        let effects = advance_to(&mut model, &mut clock, deadline);

        assert_eq!(notices(&effects), [Event::AckTimeout { usage }]);
        assert!(effects.contains(&Effect::SendSessionBye { usage }));
        assert!(
            effects.contains(&Effect::Released(Released::Exchange(exchange)))
        );
        assert!(effects.contains(&Effect::Released(Released::Replay(replay))));
        assert!(model.exchanges.get(exchange).is_none());
        assert_eq!(model.next_deadline(), None);
        let bye = model.session_bye_request(usage).unwrap().request;
        assert_eq!(bye.method(), &Method::BYE);
        assert_eq!(bye.uri().as_str(), "sip:alice@192.0.2.1");

        let started = model.bye_started(usage, Ok(())).unwrap();
        model.check();
        assert_eq!(
            notices(&model.take_effects()),
            [Event::UsageEnded { usage, reason: EndReason::AckTimeout }],
        );
        assert_eq!(model.usages.len(), 0);
        assert_eq!(model.dialogs.len(), 1, "the dialog is Mortal");
        model.bye_answered(started, Ok(()));
        model.check();
        assert_eq!(model.dialogs.len(), 0);
        assert_eq!(
            model.ended(usage),
            Some((EndReason::AckTimeout, Negotiation::Stable)),
        );

        let mut model = self::model(limits());
        let (_, _, usage) = accepted(&mut model, &clock);
        let deadline = clock.now() + T1 * 64;
        advance_to(&mut model, &mut clock, deadline);
        assert!(model.bye_started(usage, Err(Error::Unroutable)).is_none());
        model.check();
        assert_eq!(
            notices(&model.take_effects()),
            [Event::UsageEnded { usage, reason: EndReason::AckTimeout }],
        );
        assert_eq!(model.dialogs.len(), 0);
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

        model.receive_ack(&uas_dialog(), 314159, None);
        model.check();

        assert!(model.take_effects().is_empty());
        let (phase, _, _) = model.usage_state(usage).unwrap();
        assert_eq!(phase, UsagePhase::Ending, "its BYE is on its way");
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

        model.receive_ack(&uas_dialog(), 314158, None);
        let next = model.next_deadline().unwrap();
        let effects = advance_to(&mut model, &mut clock, next);
        assert_eq!(effects, [Effect::Resend2xx { exchange }]);

        model.receive_ack(&uas_dialog(), 314159, None);
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
            .try_submit(Command::Provisional {
                exchange,
                status: ringing,
                preview: None,
            })
            .unwrap();
        model.run_commands();
        assert_eq!(
            model.take_effects(),
            [Effect::SubmitProvisional {
                exchange,
                status: ringing,
                to_tag: tag.clone(),
                preview: None,
                operation: Some(operation),
            }],
        );
        model.provisional_done(
            exchange,
            ringing,
            None,
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
                    preview: None,
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
                preview: None,
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
                preview: None,
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

        let ack = model.ack_request(replay).unwrap().0;
        let again = model.ack_request(replay).unwrap().0;
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

    /// A 2xx without the answer to the INVITE's offer fails the exchange
    /// (RFC 3261 section 13.2.1). It still gets its ACK, and the session
    /// ends with a BYE once the ACK has gone, not before.
    #[test]
    fn a_2xx_without_its_answer_fails_the_negotiation() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();

        model.receive_2xx(attempt, &callee(), None).unwrap();
        model.check();

        let effects = model.take_effects();
        let (_, usage) = confirmed(&effects);
        assert!(!negotiated(&effects));
        assert!(
            notices(&effects).contains(&Event::NegotiationFailed { usage })
        );
        assert_eq!(acks(&effects).len(), 1);
        assert_eq!(session_byes(&effects, usage), 0);
        assert_eq!(
            model.usage_state(usage),
            Some((
                UsagePhase::Ending,
                Negotiation::LocalOfferOutstanding { cseq: 314159 },
                None,
            )),
        );

        model.ack_written(acks(&effects)[0], true);
        let effects = model.take_effects();
        assert_eq!(session_byes(&effects, usage), 1);
        model.bye_started(usage, Ok(())).unwrap();
        model.check();
        assert_eq!(
            model.ended(usage),
            Some((
                EndReason::NegotiationFailed,
                Negotiation::LocalOfferOutstanding { cseq: 314159 },
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
                None,
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
            matches!(ended[0], Event::UsageEnded { usage, .. } if usage != kept)
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
            .receive_2xx(
                attempt,
                &fork("bob", "sip:bob@192.0.2.4"),
                Some(answer()),
            )
            .unwrap();
        model
            .receive_2xx(
                attempt,
                &fork("carol", "sip:carol@192.0.2.5"),
                Some(answer()),
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
                let ack = model.ack_request(replay).unwrap().0.request;
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
        model.receive_provisional(attempt, &ringing, None).unwrap();
        model.receive_2xx(attempt, &kept, Some(answer())).unwrap();
        let effects = model.take_effects();
        let (session, first) = (confirmations(&effects), acks(&effects));
        assert!(negotiated(&effects));
        assert_eq!(
            model.receive_2xx(attempt, &ended, Some(answer())),
            Err(Error::CapacityExceeded),
        );
        let cleanup = acks(&model.take_effects())[0];
        model.ack_written(cleanup, true);
        assert_eq!(byes(&model.take_effects()), [cleanup]);

        model.receive_2xx(attempt, &kept, Some(answer())).unwrap();
        model.receive_2xx(attempt, &ended, Some(answer())).unwrap();
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
    /// gets a BYE of its own, and stays listed while it ends. The attempt's
    /// set of responses stays complete, since giving up was the
    /// application's choice.
    #[test]
    fn late_2xx_after_attempt_abandon_is_cleaned_up() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let early = reply("180 Ringing", "early", "sip:bob@192.0.2.4", "");
        model.receive_provisional(attempt, &early, None).unwrap();
        model
            .receive_2xx(
                attempt,
                &fork("kept", "sip:dan@192.0.2.6"),
                Some(answer()),
            )
            .unwrap();
        let kept = confirmations(&model.take_effects())[0];

        model.abandon_attempt(attempt).unwrap();
        model
            .receive_2xx(
                attempt,
                &fork("early", "sip:bob@192.0.2.4"),
                Some(answer()),
            )
            .unwrap();
        model
            .receive_2xx(
                attempt,
                &fork("late", "sip:carol@192.0.2.5"),
                Some(answer()),
            )
            .unwrap();
        let after = reply("180 Ringing", "after", "sip:eve@192.0.2.7", "");
        model.receive_provisional(attempt, &after, None).unwrap();
        model.check();

        let effects = model.take_effects();
        assert!(confirmations(&effects).is_empty());
        assert!(effects.contains(&Effect::SendSessionBye { usage: kept }));
        let early_usage = notices(&effects)
            .into_iter()
            .find_map(|event| match event {
                Event::UsageEnded { usage, .. } => Some(usage),
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
    /// settles its session, another carries none and fails its own exchange
    /// alone, and each session keeps the description its peer sent.
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
        assert_eq!(
            notices(&effects)
                .into_iter()
                .filter(|event| matches!(
                    event,
                    Event::NegotiationFailed { .. }
                ))
                .collect::<Vec<_>>(),
            [Event::NegotiationFailed { usage: sessions[1] }],
        );
        let state = |usage| {
            let (_, negotiation, remote) = model.usage_state(usage).unwrap();
            (negotiation, remote)
        };
        assert_eq!(state(sessions[0]), (Negotiation::Stable, Some(bob)));
        assert_eq!(
            state(sessions[1]),
            (Negotiation::LocalOfferOutstanding { cseq: 314159 }, None),
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
        model.receive_2xx(attempt, &kept, Some(answer())).unwrap();
        let effects = model.take_effects();
        let (session, replay) =
            (confirmations(&effects)[0], acks(&effects)[0]);
        let _ = model.receive_2xx(attempt, &ended, Some(answer()));
        let cleanup = acks(&model.take_effects())[0];
        model.ack_written(replay, true);
        model.ack_written(cleanup, true);
        model.take_effects();

        model.end_usage(session, EndReason::LocalBye);
        model.bye_done(cleanup);
        model.check();
        assert_eq!(
            model.take_effects(),
            [Effect::Notify(Event::UsageEnded {
                usage: session,
                reason: EndReason::LocalBye
            })],
        );
        assert_eq!(model.dialogs.len(), 0, "an ended session holds no dialog");
        assert!(model.has_replay(replay) && model.has_replay(cleanup));
        model.receive_2xx(attempt, &kept, Some(answer())).unwrap();
        model.receive_2xx(attempt, &ended, Some(answer())).unwrap();
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
                Some(answer()),
            )
            .unwrap();
        model.take_effects();
        let _ = model.receive_2xx(
            late,
            &late_fork("ended", "sip:carol@192.0.2.5"),
            Some(answer()),
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
            model.receive_provisional(attempt, &ringing, None).unwrap();
        }
        let second = match notices(&model.take_effects())[..] {
            [_, Event::EarlyDialog { usage, .. }] => usage,
            ref other => panic!("not two early dialogs: {other:?}"),
        };

        model
            .receive_2xx(
                attempt,
                &fork("first", "sip:bob@192.0.2.4"),
                Some(answer()),
            )
            .unwrap();
        let confirmed = model.take_effects();
        assert_eq!(
            model.receive_2xx(
                attempt,
                &fork("second", "sip:bob@192.0.2.4"),
                Some(answer())
            ),
            Err(Error::CapacityExceeded),
        );
        let early_end = model.take_effects();
        assert_eq!(
            model.receive_2xx(
                attempt,
                &fork("third", "sip:carol@192.0.2.5"),
                Some(answer())
            ),
            Err(Error::CapacityExceeded),
        );
        let beyond = model.take_effects();
        model.check();

        assert_eq!(acks(&confirmed).len(), 1);
        assert_eq!(confirmations(&early_end), []);
        assert_eq!(
            notices(&early_end),
            [Event::UsageEnded { usage: second, reason: EndReason::LocalBye }]
        );
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
                model.receive_2xx(attempt, &ok, Some(answer()))
            })
            .collect();
        let ringing = reply("180 Ringing", "early", "sip:bob@192.0.2.4", "");
        let early = model.receive_provisional(attempt, &ringing, None);
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
            model.receive_provisional(attempt, &late, None)
        };
        model
            .receive_2xx(
                attempt,
                &fork("ended", "sip:bob@192.0.2.4"),
                Some(answer()),
            )
            .unwrap();
        let session = confirmations(&model.take_effects())[0];
        model.end_usage(session, EndReason::LocalBye);
        model
            .receive_2xx(
                attempt,
                &fork("kept", "sip:dan@192.0.2.6"),
                Some(answer()),
            )
            .unwrap();
        let _ = model.receive_2xx(
            attempt,
            &fork("beyond", "sip:carol@192.0.2.5"),
            Some(answer()),
        );
        model.take_effects();
        let before = model.attempt_state(attempt).unwrap();

        assert_eq!(late(&mut model, "ended"), Ok(()));
        assert_eq!(late(&mut model, "beyond"), Ok(()));
        model.abandon_attempt(attempt).unwrap();
        model
            .receive_2xx(
                attempt,
                &fork("given", "sip:eve@192.0.2.7"),
                Some(answer()),
            )
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
            model.receive_provisional(attempt, &ringing, None).unwrap();
        }
        let third = match notices(&model.take_effects())[..] {
            [_, _, Event::EarlyDialog { usage, .. }] => usage,
            ref other => panic!("not three early dialogs: {other:?}"),
        };
        model
            .receive_2xx(
                attempt,
                &fork("first", "sip:bob@192.0.2.4"),
                Some(answer()),
            )
            .unwrap();
        let _ = model.receive_2xx(
            attempt,
            &fork("second", "sip:bob@192.0.2.4"),
            Some(answer()),
        );
        model.take_effects();

        for _ in 0..2 {
            assert_eq!(
                model.receive_2xx(
                    attempt,
                    &fork("third", "sip:carol@192.0.2.5"),
                    Some(answer())
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

    /// Where the peer's requests arrive in these tests.
    fn flow() -> Flow {
        Flow {
            transport: signa_core::transport::Transport::Udp,
            local: "192.0.2.4:5060".parse().unwrap(),
            remote: "192.0.2.1:5060".parse().unwrap(),
        }
    }

    /// A request the caller of [`INVITE`] sends in the dialog the UAS of
    /// [`accepted`] formed, numbered `cseq`.
    fn from_caller(method: &str, cseq: u32) -> Request<Bytes> {
        request(
            &INVITE
                .replace(
                    "INVITE sip:bob@biloxi.example.com",
                    &format!("{method} sip:bob@192.0.2.4"),
                )
                .replace(
                    "To: Bob <sip:bob@biloxi.example.com>",
                    "To: Bob <sip:bob@biloxi.example.com>;tag=0000000000000001",
                )
                .replace("314159 INVITE", &format!("{cseq} {method}")),
        )
    }

    /// A request the callee whose tag is `tag` sends in the dialog the 2xx
    /// of [`callee`] formed at the caller, numbered `cseq`.
    fn from_callee(method: &str, tag: &str, cseq: u32) -> Request<Bytes> {
        request(&format!(
            "{method} sip:alice@192.0.2.1 SIP/2.0
Via: SIP/2.0/UDP 192.0.2.4;branch=z9hG4bK-{method}-{cseq}
Max-Forwards: 70
To: \"Alice, A.\" <sip:alice@atlanta.example.com>;tag=1928301774
From: Bob <sip:bob@biloxi.example.com>;tag={tag}
Call-ID: a84b4c76e66710@pc33.atlanta.example.com
CSeq: {cseq} {method}
Contact: <sip:bob@192.0.2.4>

"
        ))
    }

    /// Returns the status of each final response `effects` submit.
    fn statuses(effects: &[Effect]) -> Vec<u16> {
        effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::SubmitFinal { status, .. } => Some(status.as_u16()),
                _ => None,
            })
            .collect()
    }

    /// Returns whether `effects` send the BYE of `usage`, and how often.
    fn session_byes(effects: &[Effect], usage: UsageKey) -> usize {
        effects
            .iter()
            .filter(|effect| **effect == Effect::SendSessionBye { usage })
            .count()
    }

    /// Has the callee's 2xx confirm a session of an attempt, whose ACK goes
    /// out, and returns the attempt, the session and the ACK's context.
    fn caller_session(
        model: &mut Model<Counter>,
    ) -> (AttemptKey, UsageKey, ReplayKey) {
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        let effects = model.take_effects();
        let (session, replay) =
            (confirmations(&effects)[0], acks(&effects)[0]);
        model.ack_written(replay, true);
        (attempt, session, replay)
    }

    /// Submits a command and runs it, returning its operation.
    fn run(model: &mut Model<Counter>, command: Command) -> OperationId {
        let operation = model.try_submit(command).unwrap();
        model.run_commands();
        operation
    }

    /// A CANCEL that arrives before the application decides gets the INVITE
    /// a 487 at once (RFC 3261 section 9.2), and the CANCEL's 200 the To tag
    /// of the INVITE's responses. The application is told, and its accept
    /// after that finds the final taken and sends nothing.
    #[test]
    fn cancel_wins_before_final_commit() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;

        let tag = model.receive_cancel(exchange).unwrap();
        model.check();
        assert_eq!(tag.as_str(), "0000000000000001");
        assert_eq!(
            model.take_effects(),
            [
                Effect::SubmitFinal {
                    exchange,
                    status: StatusCode::from_u16(487).unwrap(),
                    to_tag: tag,
                    body: None,
                },
                Effect::Notify(Event::InviteWithdrawn { exchange }),
            ],
        );

        let accept =
            run(&mut model, Command::Accept { authority, answer: answer() });
        assert_eq!(
            model.take_effects(),
            [Effect::OperationEnded { operation: accept }],
        );
        assert_eq!(
            model.take_outcome(accept),
            Some(Err(Error::AlreadyFinalized)),
        );
        model.final_committed(exchange, clock.now());
        model.check();
        assert!(model.exchanges.get(exchange).is_none());
        assert_eq!(model.receive_cancel(exchange), None, "nothing to cancel");
        assert_eq!(model.usages.len(), 0);
    }

    /// An accept the core has not confirmed yet wins over a CANCEL that
    /// arrives meanwhile. The CANCEL changes nothing, no 487 goes, and the
    /// session forms (RFC 3261 section 9.2). Had the core refused the 2xx,
    /// the INVITE would get the 487 rather than the 500 of an abandoned one.
    #[test]
    fn accept_wins_before_cancel_does_not_emit_487() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        let accept =
            run(&mut model, Command::Accept { authority, answer: answer() });
        assert_eq!(statuses(&model.take_effects()), [200]);

        assert!(model.receive_cancel(exchange).is_some());
        assert!(model.take_effects().is_empty());
        model.final_committed(exchange, clock.now());
        model.check();

        let effects = model.take_effects();
        assert!(statuses(&effects).is_empty());
        let (_, usage) = confirmed(&effects);
        assert_eq!(
            model.take_outcome(accept),
            Some(Ok(Completion::Session(usage))),
        );
        let tag = model.receive_cancel(exchange).unwrap();
        assert_eq!(tag.as_str(), "0000000000000001", "the dialog's tag");
        assert!(model.take_effects().is_empty(), "too late to change it");

        // The same race, with the core refusing the 2xx.
        let mut model = self::model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        run(&mut model, Command::Accept { authority, answer: answer() });
        model.receive_cancel(exchange);
        model.take_effects();
        model.final_refused(exchange, false);
        model.check();
        let effects = model.take_effects();
        assert_eq!(statuses(&effects), [487]);
        assert!(
            effects.contains(&Effect::Notify(Event::InviteWithdrawn {
                exchange
            }))
        );
    }

    /// A BYE the caller sends in the early dialog of an INVITE the
    /// application has not decided gets the INVITE a 487 (RFC 3261 section
    /// 15.1.2, RFC 5407 appendix A), and is taken for a 200. One that crosses
    /// the application's 2xx ends the session the 2xx forms, whose 2xx
    /// still goes out again until its ACK (RFC 5407 section 3.1.3).
    #[test]
    fn a_bye_in_the_early_dialog_ends_the_invite() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();

        let taken = model.receive_request(&from_caller("BYE", 314160), flow());
        model.check();
        assert_eq!(taken, Ok(InDialog::Bye));
        assert_eq!(statuses(&model.take_effects()), [487]);
        assert!(model.exchanges.get(authority.exchange).is_some());

        let mut model = self::model(limits());
        let authority = model
            .receive_invite(&request(INVITE), offer(), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        run(&mut model, Command::Accept { authority, answer: answer() });
        model.take_effects();
        let lower = model.receive_request(&from_caller("BYE", 1), flow());
        assert_eq!(lower, Err(Refusal::OutOfOrder));
        let taken = model.receive_request(&from_caller("BYE", 314160), flow());
        assert_eq!(taken, Ok(InDialog::Bye));
        model.final_committed(exchange, clock.now());
        model.check();

        let effects = model.take_effects();
        let (_, usage) = confirmed(&effects);
        let reason = EndReason::RemoteBye { flow: flow() };
        assert!(
            notices(&effects).contains(&Event::UsageEnded { usage, reason })
        );
        assert!(statuses(&effects).is_empty());
        assert_eq!(model.replays.len(), 1, "the 2xx still awaits its ACK");
        assert!(model.next_deadline().is_some());
        assert_eq!(model.ended(usage), Some((reason, Negotiation::Stable)));
    }

    /// A BYE from the peer ends its session and its dialog, and gets a 200
    /// (RFC 3261 section 15.1.2). A request in the dialog numbered at or
    /// below the last one gets a 500 and changes nothing (section 12.2.2),
    /// and one that changes nothing is answered as outside a dialog. After
    /// the BYE, the dialog is gone, and a request in it gets a 481.
    #[test]
    fn a_remote_bye_ends_the_session() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, _, usage) = accepted(&mut model, &clock);
        model.receive_ack(&uas_dialog(), 314159, None);
        model.take_effects();

        let options =
            model.receive_request(&from_caller("OPTIONS", 314160), flow());
        let stale = model.receive_request(&from_caller("BYE", 314160), flow());
        let taken = model.receive_request(&from_caller("BYE", 314170), flow());
        model.check();

        assert_eq!(options, Ok(InDialog::Other));
        assert_eq!(stale, Err(Refusal::OutOfOrder));
        assert_eq!(taken, Ok(InDialog::Bye));
        let reason = EndReason::RemoteBye { flow: flow() };
        assert_eq!(
            notices(&model.take_effects()),
            [Event::UsageEnded { usage, reason }],
        );
        assert_eq!(model.dialogs.len(), 0);
        let again = model.receive_request(&from_caller("BYE", 314171), flow());
        assert_eq!(again, Err(Refusal::NoDialog));
    }

    /// A CANCEL asked for after the INVITE went goes to the core at once,
    /// and its outcome is the operation's. It decides nothing. A 2xx that
    /// wins the race forms a session as any other, and gets its ACK (RFC
    /// 3261 sections 9.1 and 15). Asking twice is refused, and asking once
    /// the INVITE has its final is not needed.
    #[test]
    fn late_success_after_cancel_is_acked() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();

        let cancel = run(&mut model, Command::Cancel { attempt });
        assert_eq!(
            model.take_effects(),
            [Effect::CancelInvite { attempt, operation: Some(cancel) }],
        );
        model.cancel_done(Some(cancel), Ok(CancelResult::Sent));
        assert_eq!(
            model.take_outcome(cancel),
            Some(Ok(Completion::Cancel(CancelResult::Sent))),
        );
        let again = run(&mut model, Command::Cancel { attempt });
        assert_eq!(
            model.take_outcome(again),
            Some(Err(Error::InvalidTransition)),
        );
        model.take_effects();

        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        model.check();
        let effects = model.take_effects();
        assert_eq!(confirmations(&effects).len(), 1);
        assert_eq!(acks(&effects).len(), 1);
        assert_eq!(model.attempt_state(attempt).unwrap().sessions.len(), 1);

        let fresh =
            model.start_attempt(&invite("fresh@example.com"), true).unwrap();
        let busy = StatusCode::from_u16(486).unwrap();
        model.attempt_failed(fresh, Error::RemoteFailure(busy));
        let late = run(&mut model, Command::Cancel { attempt: fresh });
        assert_eq!(
            model.take_outcome(late),
            Some(Ok(Completion::Cancel(CancelResult::NotNeeded))),
        );
    }

    /// A CANCEL asked for before the core has the INVITE waits for it, and
    /// goes to the core once the INVITE does. If the INVITE never does,
    /// there was nothing to cancel.
    #[test]
    fn a_cancel_before_the_invite_starts_waits_for_it() {
        let mut model = model(limits());
        run(&mut model, Command::Invite { plan: plan() });
        let [Effect::StartInvite { attempt }] = model.take_effects()[..]
        else {
            panic!("no INVITE to send");
        };

        let cancel = run(&mut model, Command::Cancel { attempt });
        assert!(model.take_effects().is_empty());
        model.invite_started(attempt);
        let effects = model.take_effects();
        assert_eq!(
            effects[0],
            Effect::CancelInvite { attempt, operation: Some(cancel) },
        );

        run(&mut model, Command::Invite { plan: plan() });
        let [Effect::StartInvite { attempt }] = model.take_effects()[..]
        else {
            panic!("no INVITE to send");
        };
        let cancel = run(&mut model, Command::Cancel { attempt });
        model.invite_failed(attempt, Error::Unroutable);
        model.check();
        assert_eq!(
            model.take_outcome(cancel),
            Some(Ok(Completion::Cancel(CancelResult::NotNeeded))),
        );
    }

    /// Giving an attempt up is what RFC 3261 section 15 has a caller do to
    /// hang up. While the INVITE has no final, it gets its CANCEL, and an
    /// early session ends with it. Each 2xx that wins the race, from the
    /// early dialog or from a fork never seen, gets its ACK and a BYE, and no
    /// session (section 13.2.2.4).
    #[test]
    fn abandon_cleans_all_late_successful_forks() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let ringing = reply("180 Ringing", "early", "sip:bob@192.0.2.4", "");
        model.receive_provisional(attempt, &ringing, None).unwrap();
        let early = match model.take_effects()[..] {
            [Effect::Notify(Event::EarlyDialog { usage, .. })] => usage,
            ref other => panic!("no early dialog: {other:?}"),
        };

        let abandon = run(&mut model, Command::Abandon { attempt });
        model.check();
        assert_eq!(
            model.take_effects(),
            [
                Effect::CancelInvite { attempt, operation: None },
                Effect::OperationEnded { operation: abandon },
            ],
        );
        assert_eq!(model.usage_state(early).unwrap().0, UsagePhase::Ending);

        model
            .receive_2xx(
                attempt,
                &fork("early", "sip:bob@192.0.2.4"),
                Some(answer()),
            )
            .unwrap();
        model
            .receive_2xx(
                attempt,
                &fork("late", "sip:carol@192.0.2.5"),
                Some(answer()),
            )
            .unwrap();
        model.check();
        let effects = model.take_effects();
        assert!(confirmations(&effects).is_empty());
        let cleanups = acks(&effects);
        assert_eq!(cleanups.len(), 2);
        for &cleanup in &cleanups {
            model.ack_written(cleanup, true);
        }
        assert_eq!(byes(&model.take_effects()), cleanups);
        let state = model.attempt_state(attempt).unwrap();
        assert!(state.sessions.is_empty());
        assert!(state.complete && !state.degraded);

        // An attempt given up after a 2xx gets no CANCEL, which would do
        // nothing (section 9.1), and its session gets a BYE.
        let mut model = self::model(limits());
        let (attempt, session, _) = caller_session(&mut model);
        run(&mut model, Command::Abandon { attempt });
        let effects = model.take_effects();
        assert_eq!(session_byes(&effects, session), 1);
        assert!(
            !effects
                .iter()
                .any(|effect| matches!(effect, Effect::CancelInvite { .. }))
        );
    }

    /// A callee that hangs up before the ACK of its 2xx holds its BYE back
    /// (RFC 3261 section 15) and shows the session as ending. The ACK lets
    /// it go. Without an ACK, it goes at the ACK deadline, as RFC 3261
    /// section 13.3.1.4 asks anyway, and the session ends by the
    /// application's BYE.
    #[test]
    fn callee_bye_waits_for_ack_or_ack_deadline() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, _, usage) = accepted(&mut model, &clock);

        let terminate = run(&mut model, Command::Terminate { usage });
        model.check();
        assert!(model.take_effects().is_empty(), "no BYE before the ACK");
        assert_eq!(model.usage_state(usage).unwrap().0, UsagePhase::Ending);
        assert_eq!(
            model.operations.snapshot(terminate).unwrap().outcome,
            None
        );
        model.receive_ack(&uas_dialog(), 314159, None);
        model.check();
        assert_eq!(session_byes(&model.take_effects(), usage), 1);

        let mut model = self::model(limits());
        let (_, _, usage) = accepted(&mut model, &clock);
        run(&mut model, Command::Terminate { usage });
        let deadline = clock.now() + T1 * 64;
        let effects = advance_to(&mut model, &mut clock, deadline);
        assert_eq!(session_byes(&effects, usage), 1);
        model.bye_started(usage, Ok(())).unwrap();
        assert_eq!(
            notices(&model.take_effects()),
            [Event::UsageEnded { usage, reason: EndReason::LocalBye }],
        );
    }

    /// The caller may end an early session with a BYE (RFC 3261 section 15),
    /// in its early dialog, numbered after the INVITE. Its dialog is Mortal
    /// then, so a provisional for it forms nothing, and a 2xx that crossed
    /// the BYE gets its ACK and a BYE of its own, numbered after the first
    /// (RFC 5407 appendix A, RFC 3261 section 13.2.2.4).
    #[test]
    fn caller_can_end_early_invite_usage() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let ringing = reply("180 Ringing", "early", "sip:bob@192.0.2.4", "");
        model.receive_provisional(attempt, &ringing, None).unwrap();
        let early = match model.take_effects()[..] {
            [Effect::Notify(Event::EarlyDialog { usage, .. })] => usage,
            ref other => panic!("no early dialog: {other:?}"),
        };

        run(&mut model, Command::Terminate { usage: early });
        assert_eq!(session_byes(&model.take_effects(), early), 1);
        let bye = model.session_bye_request(early).unwrap().request;
        assert_eq!(bye.uri().as_str(), "sip:bob@192.0.2.4");
        assert_eq!(bye.headers().get("CSeq").unwrap(), "314160 BYE");
        assert_eq!(
            bye.headers().get("To").unwrap(),
            "<sip:bob@biloxi.example.com>;tag=early",
        );
        model.bye_started(early, Ok(())).unwrap();
        model.check();
        assert_eq!(
            notices(&model.take_effects()),
            [Event::UsageEnded { usage: early, reason: EndReason::LocalBye }],
        );

        model.receive_provisional(attempt, &ringing, None).unwrap();
        assert!(model.take_effects().is_empty());
        model
            .receive_2xx(
                attempt,
                &fork("early", "sip:bob@192.0.2.4"),
                Some(answer()),
            )
            .unwrap();
        model.check();
        let cleanup = acks(&model.take_effects())[0];
        model.ack_written(cleanup, true);
        assert_eq!(byes(&model.take_effects()), [cleanup]);
        let bye = model.bye_request(cleanup).unwrap().request;
        assert_eq!(bye.headers().get("CSeq").unwrap(), "314161 BYE");
        assert!(model.attempt_state(attempt).unwrap().complete);
    }

    /// When both sides send a BYE at once, each ends the session once. A BYE
    /// from the peer in a dialog this user agent sent its own in, which is
    /// Mortal, gets a 200 and changes nothing more, and any other request in
    /// it a 481, as does a re-INVITE (RFC 5407 sections 3.2.1 and 3.2.2). A
    /// BYE asked for after the peer's ends nothing twice. Once the BYE's
    /// transaction ends, the dialog is gone.
    #[test]
    fn crossed_bye_is_idempotent() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, session, _) = caller_session(&mut model);
        run(&mut model, Command::Terminate { usage: session });
        model.take_effects();
        let started = model.bye_started(session, Ok(())).unwrap();
        model.take_effects();

        let bye =
            model.receive_request(&from_callee("BYE", "callee", 7), flow());
        let info =
            model.receive_request(&from_callee("INFO", "callee", 8), flow());
        let reinvite = model.receive_invite(
            &from_callee("INVITE", "callee", 9),
            offer(),
            clock.now(),
        );
        let again = run(&mut model, Command::Terminate { usage: session });
        model.check();
        assert_eq!(bye, Ok(InDialog::Bye));
        assert_eq!(info, Err(Refusal::NoDialog));
        assert_eq!(reinvite.unwrap_err(), Refusal::NoDialog);
        assert_eq!(
            model.take_outcome(again),
            Some(Err(Error::InvalidTransition)),
        );
        assert!(notices(&model.take_effects()).is_empty(), "no second end");
        model.bye_answered(started, Ok(()));
        model.check();
        let late =
            model.receive_request(&from_callee("BYE", "callee", 10), flow());
        assert_eq!(late, Err(Refusal::NoDialog));

        // The peer's BYE first, while this user agent's is on its way.
        let mut model = self::model(limits());
        let (_, session, _) = caller_session(&mut model);
        let terminate = run(&mut model, Command::Terminate { usage: session });
        model.take_effects();
        let bye =
            model.receive_request(&from_callee("BYE", "callee", 7), flow());
        assert_eq!(bye, Ok(InDialog::Bye));
        let started = model.bye_started(session, Ok(())).unwrap();
        let gone = Error::RemoteFailure(StatusCode::from_u16(481).unwrap());
        model.bye_answered(started, Err(gone));
        model.check();
        let ended = notices(&model.take_effects());
        assert_eq!(ended.len(), 1, "{ended:?}");
        assert_eq!(model.dialogs.len(), 0);
        assert_eq!(model.take_outcome(terminate), Some(Err(gone)));
    }

    /// The BYE takes the dialog's next number once, however the session
    /// ends: one asked for twice, or held back for the ACK and the ACK
    /// arriving twice, still makes one BYE. A UAS that sent nothing in the
    /// dialog yet picks its first number.
    #[test]
    fn cseq_for_bye_is_allocated_once() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, session, _) = caller_session(&mut model);
        run(&mut model, Command::Terminate { usage: session });
        run(&mut model, Command::Terminate { usage: session });
        assert_eq!(session_byes(&model.take_effects(), session), 1);
        let bye = model.session_bye_request(session).unwrap().request;
        assert_eq!(bye.headers().get("CSeq").unwrap(), "314160 BYE");
        model.bye_started(session, Ok(())).unwrap();
        assert!(model.session_bye_request(session).is_err());

        let mut model = self::model(limits());
        let (_, _, usage) = accepted(&mut model, &clock);
        run(&mut model, Command::Terminate { usage });
        model.receive_ack(&uas_dialog(), 314159, None);
        model.receive_ack(&uas_dialog(), 314159, None);
        assert_eq!(session_byes(&model.take_effects(), usage), 1);
        let bye = model.session_bye_request(usage).unwrap().request;
        assert_eq!(bye.headers().get("CSeq").unwrap(), "3 BYE");
        assert_eq!(
            bye.headers().get("From").unwrap(),
            "<sip:bob@biloxi.example.com>;tag=0000000000000001",
        );
    }

    /// The session ends once the core has the BYE, before any response
    /// (RFC 3261 section 15.1.1). The operation waits for the response, and
    /// a failure there brings nothing back. A BYE the core never took leaves
    /// the session as it was, and fails the operation with nothing sent.
    #[test]
    fn bye_submission_ends_usage_before_bye_response() {
        let mut model = model(limits());
        let (_, session, _) = caller_session(&mut model);
        let terminate = run(&mut model, Command::Terminate { usage: session });
        assert_eq!(model.usage_state(session).unwrap().0, UsagePhase::Ending);
        model.take_effects();

        let started = model.bye_started(session, Ok(())).unwrap();
        model.check();
        assert_eq!(
            notices(&model.take_effects()),
            [Event::UsageEnded {
                usage: session,
                reason: EndReason::LocalBye
            }],
        );
        assert_eq!(
            model.operations.snapshot(terminate),
            Some(Snapshot { stage: Stage::Committed, outcome: None }),
        );
        let gone = Error::RemoteFailure(StatusCode::from_u16(481).unwrap());
        model.bye_answered(started, Err(gone));
        model.check();
        assert_eq!(
            model.operations.snapshot(terminate),
            Some(Snapshot {
                stage: Stage::Answered,
                outcome: Some(Err(gone))
            }),
        );
        assert_eq!(model.usage_state(session), None);

        let mut model = self::model(limits());
        let (_, session, _) = caller_session(&mut model);
        let terminate = run(&mut model, Command::Terminate { usage: session });
        let refused = Error::CoreSubmissionRejected;
        assert!(model.bye_started(session, Err(refused)).is_none());
        model.check();
        assert_eq!(model.take_outcome(terminate), Some(Err(refused)));
        assert_eq!(
            model.usage_state(session).unwrap().0,
            UsagePhase::Established,
        );
        model.take_effects();
        run(&mut model, Command::Terminate { usage: session });
        assert_eq!(session_byes(&model.take_effects(), session), 1);
    }

    /// A session the caller ended with a BYE keeps what copies of its 2xx
    /// need. A copy that comes after the BYE, before or after its response,
    /// gets the same ACK, and no new session.
    #[test]
    fn bye_does_not_destroy_invite_ack_replay() {
        let mut model = model(limits());
        let (attempt, session, replay) = caller_session(&mut model);
        run(&mut model, Command::Terminate { usage: session });
        let started = model.bye_started(session, Ok(())).unwrap();
        model.take_effects();

        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        assert_eq!(model.take_effects(), [Effect::ResendAck { replay }]);
        model.bye_answered(started, Ok(()));
        model.take_effects();
        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        model.check();
        assert_eq!(model.take_effects(), [Effect::ResendAck { replay }]);
        assert_eq!(model.usages.len(), 0);
    }

    /// Why a session ended stays for a snapshot after its notification, for
    /// the last as many sessions as the usage table holds.
    #[test]
    fn why_a_session_ended_outlives_its_notification() {
        let mut model = model(Limits { usages: 2, ..limits() });
        let mut ended = Vec::new();
        for n in 0..3 {
            let call = format!("call{n}@example.com");
            let attempt = model.start_attempt(&invite(&call), true).unwrap();
            let ok =
                callee_with("a84b4c76e66710@pc33.atlanta.example.com", &call);
            model.receive_2xx(attempt, &ok, Some(answer())).unwrap();
            let session = confirmations(&model.take_effects())[0];
            model.end_usage(session, EndReason::RemoteBye { flow: flow() });
            ended.push(session);
        }
        model.check();

        assert_eq!(model.ended(ended[0]), None, "the oldest went");
        for &session in &ended[1..] {
            let (reason, _) = model.ended(session).unwrap();
            assert_eq!(reason, EndReason::RemoteBye { flow: flow() });
        }
    }

    /// The callee's 2xx can cross the BYE that ended its early dialog and
    /// arrive after the BYE's response, as a copy the callee sends until its
    /// ACK (RFC 3261 section 13.3.1.4). The dialog is gone by then, but the
    /// attempt remembers ending it. The 2xx gets its ACK and a BYE numbered
    /// after the first, and no session, and a provisional forms nothing.
    #[test]
    fn a_2xx_after_the_bye_of_its_early_dialog_is_cleaned_up() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let ringing = reply("180 Ringing", "early", "sip:bob@192.0.2.4", "");
        model.receive_provisional(attempt, &ringing, None).unwrap();
        let early = match model.take_effects()[..] {
            [Effect::Notify(Event::EarlyDialog { usage, .. })] => usage,
            ref other => panic!("no early dialog: {other:?}"),
        };
        run(&mut model, Command::Terminate { usage: early });
        model.session_bye_request(early).unwrap();
        let started = model.bye_started(early, Ok(())).unwrap();
        model.bye_answered(started, Ok(()));
        model.take_effects();
        assert_eq!(model.dialogs.len(), 0, "the BYE is over");

        model.receive_provisional(attempt, &ringing, None).unwrap();
        assert!(model.take_effects().is_empty());
        model
            .receive_2xx(
                attempt,
                &fork("early", "sip:bob@192.0.2.4"),
                Some(answer()),
            )
            .unwrap();
        model.check();

        let effects = model.take_effects();
        assert!(confirmations(&effects).is_empty());
        let cleanup = acks(&effects)[0];
        model.ack_written(cleanup, true);
        assert_eq!(byes(&model.take_effects()), [cleanup]);
        let bye = model.bye_request(cleanup).unwrap().request;
        assert_eq!(bye.headers().get("CSeq").unwrap(), "314161 BYE");
        let state = model.attempt_state(attempt).unwrap();
        assert!(state.sessions.is_empty() && state.complete);
    }

    /// Returns the answers `effects` ask to be prepared, with the offer and
    /// the session each is for.
    fn answers_asked(
        effects: &[Effect],
    ) -> Vec<(ReplayKey, Description, Option<UsageKey>)> {
        effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::PrepareAnswer { replay, offer, usage } => {
                    Some((*replay, offer.clone(), *usage))
                }
                _ => None,
            })
            .collect()
    }

    fn failures(effects: &[Effect]) -> Vec<UsageKey> {
        notices(effects)
            .into_iter()
            .filter_map(|event| match event {
                Event::NegotiationFailed { usage } => Some(usage),
                _ => None,
            })
            .collect()
    }

    /// An offer in the INVITE gets its answer in the 2xx (RFC 3261 section
    /// 13.2.1). That completes the exchange, and the ACK carries no body.
    #[test]
    fn early_offer_answer_in_2xx() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();

        model.receive_2xx(attempt, &callee(), Some(answer())).unwrap();
        model.check();

        let effects = model.take_effects();
        let (_, usage) = confirmed(&effects);
        assert!(negotiated(&effects));
        assert!(answers_asked(&effects).is_empty());
        let (_, answered) = model.ack_request(acks(&effects)[0]).unwrap();
        assert_eq!(answered, None);
        assert_eq!(
            model.usage_state(usage),
            Some((
                UsagePhase::Established,
                Negotiation::Stable,
                Some(answer())
            )),
        );
    }

    /// An INVITE without an offer gets the offer in the 2xx, and the ACK
    /// owes the answer (RFC 3261 section 13.2.1). The ACK waits until the
    /// answer is prepared, then carries it, and only then is the exchange
    /// complete.
    #[test]
    fn offerless_invite_offer_in_2xx_answer_in_ack() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), false).unwrap();
        let (offer, mine) = (description("v=0 offer\r\n"), answer());

        model.receive_2xx(attempt, &callee(), Some(offer.clone())).unwrap();
        model.check();

        let effects = model.take_effects();
        let (_, usage) = confirmed(&effects);
        let asked = answers_asked(&effects);
        assert_eq!(asked.len(), 1);
        let (replay, asked_offer, asked_usage) = asked[0].clone();
        assert_eq!((asked_offer, asked_usage), (offer.clone(), Some(usage)));
        assert!(acks(&effects).is_empty() && !negotiated(&effects));
        assert_eq!(
            model.usage_state(usage),
            Some((
                UsagePhase::Established,
                Negotiation::RemoteOfferOutstanding { cseq: 314159 },
                Some(offer),
            )),
        );
        assert!(model.ack_request(replay).is_none(), "no ACK without it");

        model.answer_prepared(replay, Some(mine.clone()));
        model.check();

        let effects = model.take_effects();
        assert!(negotiated(&effects));
        assert_eq!(acks(&effects), [replay]);
        assert_eq!(model.ack_request(replay).unwrap().1, Some(mine));
        assert_eq!(model.usage_state(usage).unwrap().1, Negotiation::Stable);
    }

    /// A copy of the 2xx asks for no second answer. While the answer is
    /// prepared it sends nothing, and once the ACK is out it gets the same
    /// ACK, with the same answer, even if its offer differs (RFC 3261
    /// section 13.2.2.4).
    #[test]
    fn duplicate_2xx_uses_identical_prepared_answer() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), false).unwrap();
        model
            .receive_2xx(attempt, &callee(), Some(description("v=0 a\r\n")))
            .unwrap();
        let replay = answers_asked(&model.take_effects())[0].0;

        model
            .receive_2xx(attempt, &callee(), Some(description("v=0 a\r\n")))
            .unwrap();
        assert_eq!(model.take_effects(), []);

        model.answer_prepared(replay, Some(answer()));
        model.ack_written(replay, true);
        model.take_effects();
        model
            .receive_2xx(attempt, &callee(), Some(description("v=0 b\r\n")))
            .unwrap();
        model.check();

        assert_eq!(model.take_effects(), [Effect::ResendAck { replay }]);
        assert_eq!(model.ack_request(replay).unwrap().1, Some(answer()));
    }

    /// A description in an unreliable provisional is a preview. It is kept
    /// for the early session, but settles nothing, and the 2xx still has to
    /// carry the answer. One that does not fails the exchange.
    #[test]
    fn unreliable_preview_does_not_replace_final_answer_obligation() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let progress =
            reply("183 Session Progress", "callee", "sip:bob@192.0.2.4", "");

        model.receive_provisional(attempt, &progress, Some(answer())).unwrap();
        let effects = model.take_effects();
        let Event::EarlyDialog { usage, .. } = notices(&effects)[0] else {
            panic!("an early dialog");
        };
        assert!(!negotiated(&effects));
        assert_eq!(
            model.usage_state(usage),
            Some((
                UsagePhase::Establishing,
                Negotiation::LocalOfferOutstanding { cseq: 314159 },
                Some(answer()),
            )),
        );

        model.receive_2xx(attempt, &callee(), None).unwrap();
        model.check();

        let effects = model.take_effects();
        assert!(!negotiated(&effects));
        assert_eq!(failures(&effects), [usage]);
        model.ack_written(acks(&effects)[0], true);
        assert_eq!(session_byes(&model.take_effects(), usage), 1);
    }

    /// A 2xx whose answer differs from the preview is reported, and the
    /// preview stays the answer (RFC 3261 section 13.2.1, RFC 6337 section
    /// 3.1.1). One that repeats the preview, as it should, is not reported.
    #[test]
    fn conflicting_preview_and_final_answer_is_reported() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let (preview, changed) =
            (description("v=0 preview\r\n"), description("v=0 final\r\n"));
        for tag in ["bob", "carol"] {
            let progress =
                reply("183 Session Progress", tag, "sip:x@192.0.2.4", "");
            model
                .receive_provisional(attempt, &progress, Some(preview.clone()))
                .unwrap();
        }
        model.take_effects();

        model
            .receive_2xx(
                attempt,
                &fork("bob", "sip:bob@192.0.2.4"),
                Some(changed.clone()),
            )
            .unwrap();
        model
            .receive_2xx(
                attempt,
                &fork("carol", "sip:carol@192.0.2.5"),
                Some(preview.clone()),
            )
            .unwrap();
        model.check();

        let effects = model.take_effects();
        let sessions = confirmations(&effects);
        let changes: Vec<Event> = notices(&effects)
            .into_iter()
            .filter(|event| matches!(event, Event::AnswerChanged { .. }))
            .collect();
        assert_eq!(changes, [Event::AnswerChanged { usage: sessions[0] }]);
        assert_eq!(
            model.usage_state(sessions[0]).unwrap().2,
            Some(preview.clone())
        );
        assert_eq!(model.usage_state(sessions[1]).unwrap().2, Some(preview));
        assert!(!sessions.iter().any(|&usage| {
            model.usage_state(usage).unwrap().2 == Some(changed.clone())
        }));
        assert!(sessions.iter().all(|&usage| {
            model.usage_state(usage).unwrap().1 == Negotiation::Stable
        }));
    }

    /// Each fork's 2xx carries an offer of its own, and gets an answer of
    /// its own. Answering one fork, or failing to, changes nothing for the
    /// other.
    #[test]
    fn forked_offers_use_independent_answer_state() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), false).unwrap();
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
            .receive_2xx(
                attempt,
                &fork("carol", "sip:carol@192.0.2.5"),
                Some(carol.clone()),
            )
            .unwrap();
        let asked = answers_asked(&model.take_effects());
        assert_eq!(asked.len(), 2);
        assert_ne!(asked[0].0, asked[1].0);
        assert_eq!((&asked[0].1, &asked[1].1), (&bob, &carol));
        let (sessions, replays) = (
            [asked[0].2.unwrap(), asked[1].2.unwrap()],
            [asked[0].0, asked[1].0],
        );

        model.answer_prepared(replays[0], Some(answer()));
        model.check();
        let effects = model.take_effects();
        assert_eq!(acks(&effects), [replays[0]]);
        assert!(model.ack_request(replays[1]).is_none());
        assert_eq!(
            model.usage_state(sessions[1]).unwrap().1,
            Negotiation::RemoteOfferOutstanding { cseq: 314159 },
        );

        model.answer_prepared(replays[1], None);
        model.check();
        let effects = model.take_effects();
        assert_eq!(failures(&effects), [sessions[1]]);
        assert_eq!(model.usage_state(sessions[0]).unwrap().1, {
            Negotiation::Stable
        });
        assert_eq!(model.ack_request(replays[0]).unwrap().1, Some(answer()));
        assert_eq!(model.ack_request(replays[1]).unwrap().1, None);
    }

    /// An answer that comes back for a context that is gone, or already has
    /// its answer, changes nothing. A context that took over the slot of a
    /// reclaimed one keeps waiting for its own answer, since the key names
    /// the slot's generation too.
    #[test]
    fn stale_provider_completion_cannot_commit_new_exchange() {
        let mut model = model(Limits { replays: 1, ..limits() });
        let first = model.start_attempt(&request(INVITE), false).unwrap();
        model
            .receive_2xx(first, &callee(), Some(description("v=0 a\r\n")))
            .unwrap();
        let old = answers_asked(&model.take_effects())[0].0;
        model.answer_prepared(old, Some(answer()));
        model.answer_prepared(old, Some(description("v=0 late\r\n")));
        assert_eq!(model.ack_request(old).unwrap().1, Some(answer()));

        // The session ends and the responses stop, which reclaims the
        // context. A second attempt's 2xx takes the only slot there is.
        model.ack_written(old, true);
        let session = model.attempt_state(first).unwrap().sessions[0];
        model.end_usage(session, EndReason::LocalBye);
        model.response_collection_finished(first);
        assert!(!model.has_replay(old));
        let second =
            model.start_attempt(&invite("second@example.com"), false).unwrap();
        let second_2xx = callee_with(
            "a84b4c76e66710@pc33.atlanta.example.com",
            "second@example.com",
        );
        model.take_effects();
        model
            .receive_2xx(second, &second_2xx, Some(description("v=0 b\r\n")))
            .unwrap();
        let new = answers_asked(&model.take_effects())[0].0;
        assert_ne!(new, old);

        model.answer_prepared(old, Some(description("v=0 stale\r\n")));
        model.check();

        assert_eq!(model.take_effects(), []);
        assert!(model.ack_request(new).is_none(), "still waiting");
        model.answer_prepared(new, Some(answer()));
        assert_eq!(model.ack_request(new).unwrap().1, Some(answer()));
    }

    /// The 2xx of a dialog the UA does not keep, here of an attempt given
    /// up, still owes the answer to its offer in the ACK. The ACK waits for
    /// an answer that rejects the offer, and the BYE follows the ACK. Ending
    /// the dialog was the application's choice, so nothing is degraded.
    #[test]
    fn unwanted_late_offer_uses_valid_rejection_answer_then_bye() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), false).unwrap();
        model.abandon_attempt(attempt).unwrap();
        model.take_effects();
        let rejection = description("v=0 m=audio 0\r\n");

        model
            .receive_2xx(attempt, &callee(), Some(description("v=0 a\r\n")))
            .unwrap();
        model.check();
        let effects = model.take_effects();
        let asked = answers_asked(&effects);
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].2, None, "an answer that rejects");
        assert!(
            acks(&effects).is_empty() && confirmations(&effects).is_empty()
        );

        model.answer_prepared(asked[0].0, Some(rejection.clone()));
        let effects = model.take_effects();
        assert_eq!(acks(&effects), [asked[0].0]);
        assert_eq!(model.ack_request(asked[0].0).unwrap().1, Some(rejection));
        model.ack_written(asked[0].0, true);
        assert_eq!(byes(&model.take_effects()), [asked[0].0]);
        model.check();
        let state = model.attempt_state(attempt).unwrap();
        assert!(state.complete && !state.degraded);
    }

    /// No answer comes for the offer of a 2xx, as for one the SDP component
    /// cannot read, or one too late. The ACK goes anyway, without an answer,
    /// to stop the 2xx's retransmissions, the session ends with a BYE after
    /// it, and the failure shows: on the session, and on the attempt, which
    /// is degraded, since the ACK broke RFC 3261 section 13.2.1.
    #[test]
    fn malformed_late_offer_uses_bounded_best_effort_teardown_and_reports_failure()
     {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), false).unwrap();
        model
            .receive_2xx(attempt, &callee(), Some(description("garbage")))
            .unwrap();
        let effects = model.take_effects();
        let (_, usage) = confirmed(&effects);
        let replay = answers_asked(&effects)[0].0;

        model.answer_prepared(replay, None);
        model.check();

        let effects = model.take_effects();
        assert_eq!(failures(&effects), [usage]);
        assert_eq!(acks(&effects), [replay]);
        assert_eq!(session_byes(&effects, usage), 0, "not before the ACK");
        assert_eq!(model.ack_request(replay).unwrap().1, None);
        assert!(model.attempt_state(attempt).unwrap().degraded);

        model.ack_written(replay, true);
        assert_eq!(session_byes(&model.take_effects(), usage), 1);
        model.bye_started(usage, Ok(())).unwrap();
        model.check();
        assert_eq!(
            model.ended(usage).unwrap().0,
            EndReason::NegotiationFailed
        );
    }

    /// A BYE the application asks for while the ACK waits for its answer
    /// waits too, so that it does not overtake the ACK.
    #[test]
    fn a_bye_waits_for_an_ack_that_waits_for_its_answer() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), false).unwrap();
        model
            .receive_2xx(attempt, &callee(), Some(description("v=0 a\r\n")))
            .unwrap();
        let effects = model.take_effects();
        let (_, usage) = confirmed(&effects);
        let replay = answers_asked(&effects)[0].0;

        let operation = run(&mut model, Command::Terminate { usage });
        model.check();
        assert_eq!(session_byes(&model.take_effects(), usage), 0);
        assert_eq!(model.usage_state(usage).unwrap().0, UsagePhase::Ending);

        model.answer_prepared(replay, Some(answer()));
        model.ack_written(replay, true);
        model.check();

        assert_eq!(session_byes(&model.take_effects(), usage), 1);
        model.bye_started(usage, Ok(())).unwrap();
        assert_eq!(model.ended(usage).unwrap().0, EndReason::LocalBye);
        assert_eq!(model.take_outcome(operation), None, "the BYE's response");
    }

    /// The 2xx of a UAS that took an INVITE without an offer carries the
    /// application's offer, and the ACK owes the answer. An ACK that comes
    /// without one still stops the 2xx's retransmissions, since it is the
    /// ACK, but the exchange fails, and the UA ends the session with a BYE.
    #[test]
    fn an_ack_without_the_answer_it_owes_ends_the_session() {
        let mut model = model(limits());
        let clock = Clock(Instant::now());
        let authority = model
            .receive_invite(&request(INVITE), Ok(Body::Other), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        run(&mut model, Command::Accept { authority, answer: answer() });
        model.final_committed(exchange, clock.now());
        let (_, usage) = confirmed(&model.take_effects());

        model.receive_ack(&uas_dialog(), 314159, None);
        model.check();

        let effects = model.take_effects();
        assert_eq!(failures(&effects), [usage]);
        assert!(!negotiated(&effects));
        assert_eq!(session_byes(&effects, usage), 1);
        assert_eq!(model.timers.len(), 0, "no more retransmissions");
        model.bye_started(usage, Ok(())).unwrap();
        assert_eq!(
            model.ended(usage).unwrap().0,
            EndReason::NegotiationFailed
        );
    }

    /// A body the UA cannot tell the offer in gets a 415 (RFC 3261 section
    /// 8.2.3), after Require, and one with malformed Content headers a 400.
    /// A preview goes only for an INVITE with an offer, since an unreliable
    /// provisional cannot carry the offer an INVITE without one gets.
    #[test]
    fn what_an_incoming_invite_body_allows() {
        let mut model = model(limits());
        let clock = Clock(Instant::now());
        let malformed = Malformed(protocol::Field::ContentType);

        assert_eq!(
            model.receive_invite(
                &request(INVITE),
                Ok(Body::Unsupported),
                clock.now()
            ),
            Err(Refusal::UnsupportedBody),
        );
        assert_eq!(Refusal::UnsupportedBody.status().as_u16(), 415);
        assert_eq!(
            model.receive_invite(
                &request(INVITE),
                Err(malformed),
                clock.now()
            ),
            Err(Refusal::Malformed(protocol::Field::ContentType)),
        );

        let authority = model
            .receive_invite(&request(INVITE), Ok(Body::Empty), clock.now())
            .unwrap();
        let preview = run(
            &mut model,
            Command::Provisional {
                exchange: authority.exchange,
                status: StatusCode::from_u16(183).unwrap(),
                preview: Some(answer()),
            },
        );
        assert_eq!(
            model.take_outcome(preview),
            Some(Err(Error::InvalidInput))
        );
        model.check();
    }

    /// A session that ends while its ACK waits for the answer still gets
    /// that ACK, built from its dialog, once the answer is in.
    #[test]
    fn an_ack_waiting_for_its_answer_outlives_its_session() {
        let mut model = model(limits());
        let attempt = model.start_attempt(&request(INVITE), false).unwrap();
        model
            .receive_2xx(attempt, &callee(), Some(description("v=0 a\r\n")))
            .unwrap();
        let effects = model.take_effects();
        let (_, usage) = confirmed(&effects);
        let replay = answers_asked(&effects)[0].0;

        model.end_usage(usage, EndReason::Unconfirmed);
        model.check();
        model.answer_prepared(replay, Some(answer()));
        model.check();

        assert_eq!(acks(&model.take_effects()), [replay]);
        let (ack, answered) = model.ack_request(replay).unwrap();
        assert_eq!(ack.request.method(), Method::ACK);
        assert_eq!(answered, Some(answer()));
    }

    /// The responses of an attempt stop while the first ACK of a 2xx is
    /// still on its way, as for a late fork near Timer M whose next hop is
    /// slow to resolve. The ACK's record stays until its first try is over,
    /// so the BYE that waits for it still goes: the BYE of a failed exchange,
    /// and the one the application asked for while the answer was prepared.
    #[test]
    fn a_bye_after_the_ack_goes_when_the_responses_stop_first() {
        for asked in [false, true] {
            let mut model = model(limits());
            let attempt =
                model.start_attempt(&request(INVITE), false).unwrap();
            model
                .receive_2xx(attempt, &callee(), Some(description("v=0\r\n")))
                .unwrap();
            let effects = model.take_effects();
            let (_, usage) = confirmed(&effects);
            let replay = answers_asked(&effects)[0].0;
            if asked {
                run(&mut model, Command::Terminate { usage });
            }

            let answer = asked.then(answer);
            model.answer_prepared(replay, answer);
            model.response_collection_finished(attempt);
            model.check();
            assert!(model.has_replay(replay));
            model.take_effects();
            model.ack_written(replay, true);
            model.check();

            assert_eq!(session_byes(&model.take_effects(), usage), 1);
            assert!(!model.has_replay(replay));
            model.bye_started(usage, Ok(())).unwrap();
            let reason = if asked {
                EndReason::LocalBye
            } else {
                EndReason::NegotiationFailed
            };
            assert_eq!(model.ended(usage).unwrap().0, reason);
        }
    }
}
