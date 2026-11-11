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

A re-INVITE is an exchange in the dialog of a usage ([RFC 3261 section 14]).
It shares the 2xx, ACK and replay machinery of the initial INVITE, not its
lifecycle. Its failure leaves the session as it was, unless it says that the
dialog is gone. Only one INVITE transaction without a final response may be
open in a dialog at a time, which [`InviteUsage::exchange`] tracks, and a
re-INVITE that collides with another gets the 491 or the 500 of section 14.2.
The session and the remote target change apart, each at its own commit point
([RFC 6141 section 4]), and neither changes before the final response.

[RFC 3261 section 14]: https://www.rfc-editor.org/rfc/rfc3261.html#section-14
[RFC 3261 section 17]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17
[RFC 6141 section 4]: https://www.rfc-editor.org/rfc/rfc6141.html#section-4
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
        InviteExchange, InviteUsage, MergeKey, Provisional, Received, Retry,
        Scope, SentReinvite, UsageKey, UsagePhase, Withdrawal,
    },
    negotiation::{Body, Description, Negotiation},
    operation::{Completion, OperationId, Operations, Stage, SubmitError},
    plan::{Identity, InvitePlan, PlannedInvite},
    protocol::{self, Field, Malformed},
    retention::{
        AckBody, AckObligation, Bye, ReplayContext, ReplayId, ReplayKey,
        Retention, Retransmission, Source,
    },
    routing::RemoteTarget,
    slot::Slots,
    timer::{self, Timer, TimerQueue},
};

/// How often a UAS that rings sends its provisional response again.
///
/// RFC 3261 section 13.3.1.1 lets a proxy cancel an INVITE after three
/// minutes without a response, and has the UAS send a non-100 provisional
/// every minute so that a lost one does not cost the call.
const PROVISIONAL_INTERVAL: Duration = Duration::from_secs(60);

/// How many 2xx responses of one session may wait for their ACK at once.
///
/// RFC 5407 section 3.1.4 recommends taking a re-INVITE that arrives while a
/// 2xx waits for its ACK, and allows a 491 for it. I take one, and refuse a
/// re-INVITE with a 491 once two wait, so that a peer that never sends its
/// ACK cannot have one session take every replay context, each for 64 T1.
/// A 2xx that a newer re-INVITE superseded counts until its ACK deadline
/// too. It ends nothing then, but holds its context as long, and not counting
/// it would let each new re-INVITE free room for the next.
const UNACKNOWLEDGED: usize = 2;

/// A source of randomness for tags and Call-IDs, the retry timer of a 491
/// and the Retry-After of a 500 that refuses an overlapping INVITE.
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
    /// Exchanges of re-INVITEs, in either direction. Those of incoming
    /// INVITEs and of attempts come on top, so that re-INVITEs cannot take
    /// their room. A re-INVITE this user agent sent keeps its record until
    /// the core stops collecting its responses.
    pub(crate) reinvites: usize,
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
    /// Send a re-INVITE in the dialog of a session, with `offer` or, for a
    /// late offer, without one.
    Reinvite { usage: UsageKey, offer: Option<Description> },
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
    /// Send a re-INVITE, which [`Model::take_reinvite`] hands over, then
    /// report the outcome with [`Model::reinvite_started`], and its
    /// responses as for an attempt, with
    /// [`Model::receive_reinvite_response`] and the others for a re-INVITE.
    StartReinvite { exchange: ExchangeKey },
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
    /// Its body is one the UA cannot tell the offer in, such as a multipart
    /// body. A 415 (RFC 3261 section 8.2.3).
    UnsupportedBody,
    /// Its offer is larger than the UA keeps of a session description. A
    /// 413, which RFC 3261 section 21.4.11 gives a body larger than the
    /// server is willing to process. The limit is my policy.
    TooLarge,
    /// It is a re-INVITE that collides with an INVITE this user agent sent in
    /// the dialog and has no final response for. A 491 (RFC 3261 section
    /// 14.2). So is one while an offer of this user agent's waits for its
    /// answer (RFC 5407 section 3.1.5), and, by my policy, one in a session
    /// this user agent is ending.
    RequestPending,
    /// It is an INVITE that arrived before this user agent sent the final
    /// response to an INVITE with a lower CSeq in the same dialog. A 500 with
    /// a Retry-After of the given seconds, chosen at random from 0 to 10
    /// (RFC 3261 section 14.2).
    Overlapping(u8),
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
            Refusal::TooLarge => 413,
            Refusal::UnsupportedBody => 415,
            Refusal::SipsRequestUri => 416,
            Refusal::BadExtension => 420,
            Refusal::SipsNotAllowed => 480,
            Refusal::NoDialog => 481,
            Refusal::Merged => 482,
            Refusal::RequestPending => 491,
            Refusal::RouteSetTooLong
            | Refusal::OutOfOrder
            | Refusal::Overlapping(_)
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
    /// The caller gave an INVITE up before the application decided it, or
    /// the session of a re-INVITE ended first, and the UA answered it with a
    /// 487.
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

/// Where a usage stands, as a snapshot shows it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UsageState {
    pub(crate) phase: UsagePhase,
    pub(crate) negotiation: Negotiation,
    pub(crate) remote: Option<Description>,
    pub(crate) session_revision: u32,
    pub(crate) target_revision: u32,
    pub(crate) end_reason: Option<EndReason>,
}

/// What a usage that ended leaves for its snapshot.
#[derive(Clone, Copy, Debug)]
struct Ended {
    usage: UsageKey,
    reason: EndReason,
    negotiation: Negotiation,
    session_revision: u32,
    target_revision: u32,
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
    ended: VecDeque<Ended>,
    /// How many of `exchanges` are for re-INVITEs, within
    /// `limits.reinvites`.
    reinvites: usize,
    timers: TimerQueue,
    operations: Operations,
    commands: VecDeque<(OperationId, Command)>,
    effects: Vec<Effect>,
    /// The operations the runtime holds until it reports their outcome, as
    /// for a provisional response on its way to the core. No record of the
    /// model's holds them then. Only the tests' checks read this, to find
    /// an operation nothing can end any more.
    #[cfg(test)]
    handed: std::collections::HashSet<OperationId>,
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
                limits
                    .incoming
                    .saturating_add(limits.attempts)
                    .saturating_add(limits.reinvites),
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
            reinvites: 0,
            timers: TimerQueue::default(),
            operations: Operations::new(limits.operations),
            commands: VecDeque::new(),
            effects: Vec::new(),
            #[cfg(test)]
            handed: std::collections::HashSet::new(),
        }
    }

    /// Returns the effects of the inputs so far, in order.
    ///
    /// In the tests it checks what must hold between the tables too, so that
    /// every input a test feeds is checked.
    pub(crate) fn take_effects(&mut self) -> Vec<Effect> {
        #[cfg(test)]
        self.check();
        std::mem::take(&mut self.effects)
    }

    /// Notes that the runtime holds `operation` until it reports the
    /// outcome, for the tests' checks.
    fn hand_over(&mut self, operation: Option<OperationId>) {
        #[cfg(test)]
        self.handed.extend(operation);
        #[cfg(not(test))]
        let _ = operation;
    }

    /// Notes that the runtime reported the outcome of `operation`.
    fn take_back(&mut self, operation: Option<OperationId>) {
        #[cfg(test)]
        if let Some(operation) = operation {
            self.handed.remove(&operation);
        }
        #[cfg(not(test))]
        let _ = operation;
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
                Command::Reinvite { usage, offer } => {
                    if let Err(error) =
                        self.reinvite(Some(operation), usage, offer, false)
                    {
                        self.complete(operation, Err(error));
                    }
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
                Timer::Retry(usage) => self.retry_due(usage),
            }
        }
    }

    /// Returns where a usage stands, or `None` once it has been reclaimed
    /// and is no longer among the last ones to end. One that ended has no
    /// session description any more.
    pub(crate) fn usage_state(&self, key: UsageKey) -> Option<UsageState> {
        let Some(usage) = self.usages.get(key) else {
            let ended = self.ended(key)?;
            return Some(UsageState {
                phase: UsagePhase::Ended,
                negotiation: ended.negotiation,
                remote: None,
                session_revision: ended.session_revision,
                target_revision: ended.target_revision,
                end_reason: Some(ended.reason),
            });
        };

        let target_revision =
            self.dialogs.get(usage.dialog).map_or(0, Dialog::target_revision);
        Some(UsageState {
            phase: usage.phase(),
            negotiation: usage.negotiation,
            remote: usage.remote.clone(),
            session_revision: usage.revision,
            target_revision,
            end_reason: None,
        })
    }

    /// Returns why a usage ended, and where it stood then, as long as it is
    /// among the last ones to end.
    fn ended(&self, usage: UsageKey) -> Option<Ended> {
        self.ended.iter().rev().find(|ended| ended.usage == usage).copied()
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

    /// Says whether a request belongs to a dialog this user agent keeps, or
    /// to the early dialog of an INVITE it has not answered, which tells a
    /// BYE that ends something from one that ends nothing. A Mortal dialog
    /// does not count, since a BYE there ends nothing more.
    // Only the runtime asks.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn knows_dialog<B>(&self, request: &Request<B>) -> bool {
        matches!(
            request_dialog(request),
            Ok(Some(id)) if self
                .dialog_index
                .get(&id)
                .is_some_and(|&dialog| !self.is_mortal(dialog))
                || self.early_index.contains_key(&id)
        )
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
    ///
    /// An INVITE with a To tag is a re-INVITE, which
    /// [`Model::receive_reinvite`] takes. One in the early dialog of an
    /// INVITE this user agent has not answered yet comes before that answer,
    /// and gets the 500 of RFC 3261 section 14.2.
    pub(crate) fn receive_invite<B>(
        &mut self,
        request: &Request<B>,
        body: Result<Body, Malformed>,
        now: Instant,
    ) -> Result<Authority, Refusal> {
        let dialog = match self.classify(request)? {
            Incoming::Initial => None,
            Incoming::NoDialog => {
                let id = request_dialog(request)?.expect("tagged");
                if self.early_index.contains_key(&id) {
                    return Err(Refusal::Overlapping(self.retry_after()));
                }
                return Err(Refusal::NoDialog);
            }
            // A dialog this user agent sent a BYE in is Mortal, and a
            // re-INVITE in it gets a 481 (RFC 5407 section 3.2.2).
            Incoming::InDialog(dialog) if self.is_mortal(dialog) => {
                return Err(Refusal::NoDialog);
            }
            Incoming::InDialog(dialog) => Some(dialog),
        };
        if protocol::is_sips(request.uri().as_str()) {
            return Err(Refusal::SipsRequestUri);
        }
        if let Some(dialog) = dialog {
            return self.receive_reinvite(dialog, request, body, now);
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
            Body::TooLarge => return Err(Refusal::TooLarge),
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
        let (decision_due, expires_due) = self.decision_times(expires, now);
        let cseq = merge.cseq;
        let exchange = InviteExchange::incoming(
            Received::Initial {
                dialog: Some(Box::new(dialog)),
                merge: merge.clone(),
            },
            cseq,
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
        self.set_decision_timers(exchange, decision_due, expires_due);
        Ok(Authority { exchange })
    }

    /// Takes in a re-INVITE in a live dialog of this user agent's
    /// ([RFC 3261 section 14.2]).
    ///
    /// The checks of section 8.2 come first: Require, then the body. Then
    /// the CSeq, as for any request in a dialog (section 12.2.2), and then
    /// whether another INVITE of the dialog is still open:
    ///
    /// * One this user agent sent and has no final response for gets the
    ///   re-INVITE a 491 (section 14.2). So does the early dialog of an
    ///   initial INVITE this user agent sent, whose transaction is still
    ///   open.
    /// * One this user agent received and has not answered gets it a 500
    ///   with a random Retry-After of 0 to 10 seconds (section 14.2).
    /// * An offer of this user agent's that waits for its answer, as in the
    ///   2xx of an INVITE without one before its ACK, gets it a 491, which
    ///   [RFC 5407 section 3.1.5] recommends. A 2xx that only waits for its
    ///   ACK holds nothing up, as section 3.1.4 recommends.
    /// * A session this user agent is ending gets it a 491 too, by my policy,
    ///   since a re-INVITE there would change nothing. The peer learns of the
    ///   BYE before it would try again.
    /// * So does a session with two 2xx responses of this user agent's that
    ///   wait for their ACK, by my policy, which section 3.1.4 allows (see
    ///   [`UNACKNOWLEDGED`]).
    ///
    /// Nothing in the dialog changes until the re-INVITE is taken, since
    /// section 12.2 has a request that is refused change no state. Taken,
    /// it records its CSeq. The new remote target in its Contact waits for
    /// the 2xx, as [RFC 6141 section 4.6] has a UAS replace the target only
    /// when it answers with a 2xx or a reliable provisional response, never
    /// with an error. A Contact that cannot be a target is refused with a 400
    /// up front.
    ///
    /// [RFC 3261 section 14.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-14.2
    /// [RFC 5407 section 3.1.5]: https://www.rfc-editor.org/rfc/rfc5407.html#section-3.1.5
    /// [RFC 6141 section 4.6]: https://www.rfc-editor.org/rfc/rfc6141.html#section-4.6
    fn receive_reinvite<B>(
        &mut self,
        dialog: DialogKey,
        request: &Request<B>,
        body: Result<Body, Malformed>,
        now: Instant,
    ) -> Result<Authority, Refusal> {
        let headers = request.headers();
        if protocol::requires_extension(headers)? {
            return Err(Refusal::BadExtension);
        }
        let offer = match body? {
            Body::Session(offer) => Some(offer),
            Body::Empty | Body::Other => None,
            Body::Unsupported => return Err(Refusal::UnsupportedBody),
            Body::TooLarge => return Err(Refusal::TooLarge),
        };
        let (cseq, _) = protocol::cseq(headers)?;
        // The index and the table change together, so a dialog the index
        // names is there. One that were not would be no dialog to take a
        // re-INVITE in.
        let record = self.dialogs.get(dialog).ok_or(Refusal::NoDialog)?;
        record.check_remote(cseq).map_err(out_of_order)?;
        let id = record.id().clone();
        let usage_key = self.usage_of(dialog).ok_or(Refusal::NoDialog)?;
        self.supersede(usage_key, cseq);

        let usage = self.usages.get(usage_key).expect("found");
        if let Some(open) = usage.exchange {
            let received = self.exchanges.get(open).is_some_and(|open| {
                matches!(open.scope, Scope::Incoming { .. })
            });
            return Err(if received {
                Refusal::Overlapping(self.retry_after())
            } else {
                Refusal::RequestPending
            });
        }
        // A re-INVITE of this user agent's that waits to go again after a
        // 491 holds nothing up. The peer's own second try comes first when
        // this user agent owns the Call-ID, and has to get through, or the
        // two would collide again (RFC 3261 section 14.1).
        let unacknowledged = self
            .replays
            .iter()
            .filter(|(_, replay)| {
                replay.usage == Some(usage_key)
                    && replay.ack == AckObligation::AwaitingPeer
            })
            .count();
        if usage.phase() != UsagePhase::Established
            || usage.negotiation != Negotiation::Stable
            || unacknowledged >= UNACKNOWLEDGED
        {
            return Err(Refusal::RequestPending);
        }
        let contact = protocol::contact(headers)?;
        if contact.is_some_and(|contact| RemoteTarget::new(contact).is_err()) {
            return Err(Refusal::Malformed(Field::Contact));
        }
        let expires = protocol::expires(headers)?;

        if self.reinvites >= self.limits.reinvites {
            return Err(Refusal::Busy);
        }
        let (decision_due, expires_due) = self.decision_times(expires, now);
        let exchange = InviteExchange::incoming(
            Received::Reinvite {
                usage: usage_key,
                dialog: id,
                contact: contact.map(Into::into),
            },
            cseq,
            offer,
            decision_due,
            expires_due,
        );
        let Ok(exchange) = self.exchanges.insert(exchange) else {
            return Err(Refusal::Busy);
        };

        self.reinvites += 1;
        self.dialogs
            .get_mut(dialog)
            .expect("indexed")
            .remote_request(cseq)
            .expect("checked above");
        self.usages.get_mut(usage_key).expect("found").exchange =
            Some(exchange);
        self.set_decision_timers(exchange, decision_due, expires_due);
        Ok(Authority { exchange })
    }

    /// Marks the 2xx responses of earlier re-INVITEs of a usage that still
    /// wait for their ACK as superseded by the peer's re-INVITE numbered
    /// `cseq`.
    ///
    /// RFC 6141 section 5.4 has a UAS that accepted a re-INVITE, which is a
    /// target refresh, and never gets its ACK, keep the dialog if it
    /// received a re-INVITE with a higher CSeq, rather than end it with the
    /// BYE of RFC 3261 section 14.2. The peer lost its old contact, so it
    /// never got the 2xx, and the newer re-INVITE carries its new one. The
    /// section asks only that it was received, so a re-INVITE refused for
    /// another reason, such as a 491, counts too, once its CSeq shows it is
    /// newer. The 2xx of the initial INVITE is not marked, since RFC 5407
    /// section 3.1.4 still ends a dialog whose first ACK never comes.
    fn supersede(&mut self, usage: UsageKey, cseq: u32) {
        let older: Vec<ReplayKey> = self
            .replays
            .iter()
            .filter(|(_, replay)| {
                replay.usage == Some(usage)
                    && replay.ack == AckObligation::AwaitingPeer
                    && replay.id.cseq < cseq
                    && matches!(
                        replay.source,
                        Source::Exchange(exchange)
                            if self.exchanges.get(exchange).is_some_and(
                                |exchange| exchange.reinvite_usage().is_some(),
                            )
                    )
            })
            .map(|(replay, _)| replay)
            .collect();

        for replay in older {
            self.replays.get_mut(replay).expect("listed").superseded = true;
        }
    }

    /// Returns when the application's decision on an INVITE is due, and
    /// when the INVITE expires, if its Expires says. A time too far off to
    /// add to the clock sets no deadline, rather than overflow.
    fn decision_times(
        &self,
        expires: Option<u32>,
        now: Instant,
    ) -> (Option<Instant>, Option<Instant>) {
        let decision_due = now.checked_add(self.limits.decision_timeout);
        let expires_due = expires.and_then(|seconds| {
            now.checked_add(Duration::from_secs(seconds.into()))
        });
        (decision_due, expires_due)
    }

    fn set_decision_timers(
        &mut self,
        exchange: ExchangeKey,
        decision_due: Option<Instant>,
        expires_due: Option<Instant>,
    ) {
        if let Some(due) = decision_due {
            self.timers.set(due, Timer::Decision(exchange));
        }
        if let Some(due) = expires_due {
            self.timers.set(due, Timer::Expires(exchange));
        }
    }

    /// Picks the Retry-After of a 500 that refuses an overlapping INVITE,
    /// at random from 0 to 10 seconds, as RFC 3261 section 14.2 asks. A
    /// source of randomness that fails gives the middle of the range.
    fn retry_after(&mut self) -> u8 {
        self.random.next_u64().map_or(5, |random| (random % 11) as u8)
    }

    /// Returns the usage that holds a live dialog.
    fn usage_of(&self, dialog: DialogKey) -> Option<UsageKey> {
        self.usages.iter().find_map(|(usage, record)| {
            (record.dialog == dialog).then_some(usage)
        })
    }

    /// Returns the session a re-INVITE this user agent received is for, or
    /// `None` for an initial INVITE.
    pub(crate) fn reinvite_session(
        &self,
        exchange: ExchangeKey,
    ) -> Option<UsageKey> {
        match &self.exchanges.get(exchange)?.scope {
            Scope::Incoming {
                kind: Received::Reinvite { usage, .. }, ..
            } => Some(*usage),
            _ => None,
        }
    }

    /// Returns the To tag every response of an incoming exchange carries,
    /// while its dialog is known. That is the tag chosen for an initial
    /// INVITE until its 2xx forms the dialog, or the local tag of a
    /// re-INVITE's dialog.
    fn response_tag(exchange: &InviteExchange) -> Option<Tag> {
        match &exchange.scope {
            Scope::Incoming {
                kind: Received::Initial { dialog: Some(dialog), .. },
                ..
            } => Some(dialog.id().local_tag().clone()),
            Scope::Incoming {
                kind: Received::Reinvite { dialog, .. },
                ..
            } => Some(dialog.local_tag().clone()),
            _ => None,
        }
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
        let to_tag = Model::<R>::response_tag(exchange)
            .expect("a pending incoming exchange knows its dialog");
        let reinvite = exchange.reinvite_usage().is_some();

        // The dialog, the usage and the replay context of a 2xx are set
        // aside before it goes out, so it never goes out without them. A
        // re-INVITE's 2xx needs the replay context only. `final_committed`
        // uses them, and `final_refused` gives them back.
        let reserved = !status.is_success()
            || if reinvite {
                self.reserve_replay()
            } else {
                self.reserve_session()
            };
        if !reserved {
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
        let Scope::Incoming { offer, .. } = &exchange.scope else {
            unreachable!("only incoming exchanges send responses");
        };
        // A 100 is the core's to send (RFC 3261 section 17.2.1).
        if !(101..=199).contains(&status.as_u16())
            || (preview.is_some() && offer.is_none())
        {
            self.complete(operation, Err(Error::InvalidInput));
            return;
        }

        let to_tag = Model::<R>::response_tag(exchange)
            .expect("a pending incoming exchange knows its dialog");
        self.hand_over(Some(operation));
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
        self.take_back(operation);
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
        let due = later(now, PROVISIONAL_INTERVAL);
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
        let Some(to_tag) = Model::<R>::response_tag(exchange) else {
            return;
        };
        let Scope::Incoming { provisional: Some(provisional), .. } =
            &mut exchange.scope
        else {
            return;
        };

        let next = after(at, PROVISIONAL_INTERVAL, now);
        provisional.due = next;
        self.timers.set(next, Timer::Provisional(key));
        self.effects.push(Effect::SubmitProvisional {
            exchange: key,
            status: provisional.status,
            to_tag,
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
    /// merge index, and has the runtime let go of its responder. A
    /// re-INVITE's usage lets go of it too, if it has not yet.
    fn drop_exchange(&mut self, key: ExchangeKey) {
        self.stop_exchange_timers(key);
        let Some(exchange) = self.exchanges.remove(key) else {
            return;
        };

        match &exchange.scope {
            Scope::Incoming {
                kind: Received::Initial { merge, dialog },
                ..
            } => {
                if self.merge_index.get(merge) == Some(&key) {
                    self.merge_index.remove(merge);
                }
                if let Some(dialog) = dialog {
                    self.forget_early(dialog.id(), key);
                }
            }
            Scope::Incoming {
                kind: Received::Reinvite { usage, .. }, ..
            } => {
                self.reinvites -= 1;
                self.let_go(*usage, key);
            }
            Scope::Outgoing | Scope::Reinvite(_) => {}
        }
        self.effects.push(Effect::Released(Released::Exchange(key)));
    }

    /// Has a usage let go of the INVITE exchange it held open, once that
    /// exchange has its final response.
    fn let_go(&mut self, usage: UsageKey, exchange: ExchangeKey) {
        if let Some(usage) = self.usages.get_mut(usage) {
            if usage.exchange == Some(exchange) {
                usage.exchange = None;
            }
        }
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
        let usage = match &mut exchange.scope {
            Scope::Incoming {
                kind: Received::Reinvite { usage, .. }, ..
            } => Some(*usage),
            _ => None,
        };
        let usage = match usage {
            Some(usage) => self.commit_reinvite(key, usage, cseq),
            None => self.commit_initial(key, cseq),
        };
        let replay_dialog =
            self.replays.iter().find_map(|(replay, context)| {
                (context.source == Source::Exchange(key))
                    .then(|| (replay, context.id.dialog.clone()))
            });
        let (replay, replay_dialog) =
            replay_dialog.expect("a committed 2xx has its replay context");

        // RFC 3261 section 13.3.1.4 has the 2xx go out again T1 later, and
        // gives up on its ACK 64 T1 after the first. Section 14.2 asks the
        // same of the 2xx of a re-INVITE.
        // signa-core's `Timers` checked that 64 T1 multiplies.
        let (t1, deadline) = (self.limits.t1, later(now, self.limits.t1 * 64));
        let next = Some(later(now, t1)).filter(|&next| next < deadline);
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

    /// Forms the dialog and the usage of an initial INVITE whose 2xx the
    /// core took, with the replay context of that 2xx, and returns the
    /// usage.
    fn commit_initial(&mut self, key: ExchangeKey, cseq: u32) -> UsageKey {
        let exchange = self.exchanges.get_mut(key).expect("checked");
        let Scope::Incoming {
            kind: Received::Initial { dialog, .. },
            offer,
            withdrawn,
            ..
        } = &mut exchange.scope
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
        let replay = ReplayId {
            dialog: dialog.id().clone(),
            cseq,
            direction: Direction::Incoming,
        };
        let (_, usage) = self.establish(
            dialog,
            Direction::Incoming,
            negotiation,
            replay,
            Source::Exchange(key),
        );
        self.usages.get_mut(usage).expect("just made").remote = offer;
        if offer_in_request {
            self.negotiated(usage);
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
        usage
    }

    /// Takes in the 2xx of a re-INVITE that the core took, with the replay
    /// context set aside for it, and returns the usage.
    ///
    /// The 2xx commits the new remote target of the re-INVITE's Contact
    /// ([RFC 6141 section 4.6]), and its offer/answer exchange. With an
    /// offer in the re-INVITE, the 2xx carried the answer, so the session
    /// takes its next revision now. Without one, the 2xx carried an offer,
    /// and the revision waits for the answer in the ACK (RFC 3261 section
    /// 13.2.1). The target does not wait for it, and stays when the exchange
    /// fails, since the two are not one atomic change (RFC 6141 section
    /// 4.3).
    ///
    /// The session may have ended while the 2xx was on its way, by a BYE in
    /// either direction. The 2xx then changes nothing, but still goes out
    /// again until its ACK (RFC 3261 section 13.3.1.4), which needs its
    /// replay context.
    ///
    /// [RFC 6141 section 4.6]: https://www.rfc-editor.org/rfc/rfc6141.html#section-4.6
    fn commit_reinvite(
        &mut self,
        key: ExchangeKey,
        usage: UsageKey,
        cseq: u32,
    ) -> UsageKey {
        let exchange = self.exchanges.get_mut(key).expect("checked");
        let Scope::Incoming {
            kind: Received::Reinvite { dialog: id, contact, .. },
            offer,
            ..
        } = &mut exchange.scope
        else {
            unreachable!("checked by the caller");
        };
        let (offer, contact) = (offer.take(), contact.take());
        let replay = ReplayId {
            dialog: id.clone(),
            cseq,
            direction: Direction::Incoming,
        };

        let context =
            ReplayContext::new(replay.clone(), Source::Exchange(key), usage);
        let context = self.replays.insert_reserved(context);
        self.replay_index.insert(replay, context);
        self.let_go(usage, key);
        let Some(record) = self.usages.get_mut(usage) else {
            self.replays.get_mut(context).expect("just made").usage_ended();
            return usage;
        };

        match offer {
            Some(offer) => {
                record.negotiation.offer_received(cseq).expect("stable");
                record
                    .negotiation
                    .answer_sent(cseq)
                    .expect("the offer is outstanding");
                record.remote = Some(offer);
                self.negotiated(usage);
            }
            None => {
                record.negotiation.offer_sent(cseq).expect("stable");
            }
        }
        let dialog = self.usages.get(usage).expect("checked").dialog;
        if let (Some(contact), Some(dialog)) =
            (contact, self.dialogs.get_mut(dialog))
        {
            dialog.refresh_to(&contact).expect("checked when it arrived");
        }
        usage
    }

    /// Completes the offer/answer exchange of a usage. The session takes its
    /// next revision, and the application hears of it.
    fn negotiated(&mut self, usage: UsageKey) {
        if let Some(record) = self.usages.get_mut(usage) {
            record.revision = record.revision.wrapping_add(1);
            self.effects
                .push(Effect::Notify(Event::NegotiationCompleted { usage }));
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
                && match &exchange.scope {
                    Scope::Incoming {
                        kind: Received::Initial { dialog: Some(pending), .. },
                        ..
                    } => pending.id() == dialog,
                    Scope::Incoming {
                        kind: Received::Reinvite { dialog: pending, .. },
                        ..
                    } => pending == dialog,
                    _ => false,
                }
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

        let reinvite = exchange.reinvite_usage();
        if status.is_success() {
            if reinvite.is_none() {
                self.dialogs.release();
                self.usages.release();
            }
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
        // A BYE that waited for the ACK of a re-INVITE's 2xx has none to
        // wait for now.
        if let Some(usage) = reinvite {
            self.release_bye(usage);
        }
    }

    /// Returns how the caller gave up an incoming INVITE, if it did.
    fn withdrawn(&self, key: ExchangeKey) -> Option<Withdrawal> {
        match &self.exchanges.get(key)?.scope {
            Scope::Incoming { withdrawn, .. } => withdrawn.as_deref().copied(),
            Scope::Outgoing | Scope::Reinvite(_) => None,
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
            // The 2xx of an initial INVITE went, and the dialog with it, so
            // the tag is the dialog's. The CANCEL changes nothing then.
            Scope::Incoming {
                kind: Received::Initial { dialog: None, .. },
                ..
            } => {
                return self.committed_tag(key);
            }
            // A re-INVITE's CANCEL is taken as an initial INVITE's. One that
            // gets its 487 leaves the session as it was (section 14.1).
            _ => Model::<R>::response_tag(exchange)?,
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
            // A dialog that is not Mortal is in the table with its usage,
            // since the index, the table and the usages change together.
            // Were either missing, the request would find no dialog, and
            // nothing changes before it is found.
            let usage = self.usage_of(key);
            let (Some(dialog), Some(usage)) =
                (self.dialogs.get_mut(key), usage)
            else {
                return Err(Refusal::NoDialog);
            };
            dialog.remote_request(cseq).map_err(out_of_order)?;
            if !bye {
                return Ok(InDialog::Other);
            }

            self.end_usage(usage, EndReason::RemoteBye { flow });
            return Ok(InDialog::Bye);
        }

        let Some(&key) = self.early_index.get(&id) else {
            return Err(Refusal::NoDialog);
        };
        let Some(InviteExchange {
            scope:
                Scope::Incoming {
                    kind: Received::Initial { dialog: Some(dialog), .. },
                    ..
                },
            ..
        }) = self.exchanges.get_mut(key)
        else {
            // The index lets go of an exchange before its dialog goes, so
            // this does not happen. Were it to, there is no early dialog.
            return Err(Refusal::NoDialog);
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
                        record.revision = record.revision.wrapping_add(1);
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
    ///
    /// The 2xx of a re-INVITE that a newer re-INVITE of the peer's
    /// superseded only stops, and the session goes on, as RFC 6141 section
    /// 5.4 recommends. A BYE the application asked for goes now all the
    /// same. That is not so when the 2xx carried an offer whose answer the
    /// missing ACK owed. The exchange can then never complete, and no later
    /// one can start, so the session ends as above.
    fn ack_overdue(&mut self, key: ReplayKey) {
        let Some(replay) = self.replays.get_mut(key) else {
            return;
        };
        if replay.ack != AckObligation::AwaitingPeer {
            return;
        }

        replay.ack = AckObligation::Failed;
        replay.duplicates_ended();
        let (usage, source, cseq) =
            (replay.usage, replay.source, replay.id.cseq);
        let superseded = replay.superseded;

        self.stop_retransmission(key);
        if let Source::Exchange(exchange) = source {
            self.drop_exchange(exchange);
        }
        let moot = superseded
            && usage
                .and_then(|usage| self.usages.get(usage))
                .is_some_and(|usage| !usage.negotiation.awaits_answer(cseq));
        if let (true, Some(usage)) = (moot, usage) {
            self.release_bye(usage);
            self.reclaim_replay(key);
            return;
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

/// Returns `by` after `at`, or as late as the clock goes. A timer set from
/// a configured time too long to add to the clock is then due as late as it
/// can be, rather than overflow, which only a T1 or a T2 of thousands of years
/// could ask for.
fn later(at: Instant, by: Duration) -> Instant {
    at.checked_add(by).or_else(|| at.checked_add(timer::FAR)).unwrap_or(at)
}

/// Returns `interval` after `at`, the time a timer was due, or after `now`
/// when that has passed too, so that a late driver sends one copy rather
/// than a burst to catch up.
fn after(at: Instant, interval: Duration, now: Instant) -> Instant {
    let next = later(at, interval);
    if next > now { next } else { later(now, interval) }
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
            self.hand_over(cancel);
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
            self.hand_over(operation);
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
        self.take_back(operation);
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
        // An early dialog in the table has its usage, since a usage the
        // UA ends takes its dialog out, or leaves it Mortal, which
        // `ended_early` covers before this is called. A 2xx for a dialog
        // without one could not be taken, and leaves the attempt incomplete.
        let Some(usage) = record.forks.iter().copied().find(|&usage| {
            self.usages.get(usage).is_some_and(|usage| usage.dialog == dialog)
        }) else {
            return Err(Error::InvalidInput);
        };
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
                record.revision = record.revision.wrapping_add(1);
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
        let operation = context.operation.take();
        let answered = answer.is_some();
        context.ack_body = match answer {
            Some(answer) => AckBody::Answer(answer),
            None => AckBody::Unanswered,
        };
        let attempt = match source {
            Source::Attempt(attempt) => self.attempts.get_mut(attempt),
            Source::Exchange(_) | Source::Reinvite(_) => None,
        };
        if let (false, Some(record)) = (answered, attempt) {
            record.degraded = true;
        }

        let alive = usage.filter(|&usage| self.usages.get(usage).is_some());
        if let Some(usage) = alive {
            if answered {
                let record = self.usages.get_mut(usage).expect("checked");
                if record.negotiation.answer_sent(cseq).is_ok() {
                    self.negotiated(usage);
                }
            } else {
                self.fail_negotiation(usage);
            }
        }
        // The operation of a re-INVITE without an offer ends with its
        // answer, or with its session, if that ended first.
        if let Some(operation) = operation {
            let outcome = match (alive, answered) {
                (None, _) => Err(Error::SessionEnded),
                (Some(_), true) => Ok(Completion::Done),
                (Some(_), false) => Err(Error::NegotiationFailure),
            };
            self.complete(operation, outcome);
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

/// Re-INVITEs this user agent sends.
impl<R: Random> Model<R> {
    /// Sends a re-INVITE in the dialog of a session, with `offer`, or
    /// without one for a late offer, for `operation` if the application
    /// asked. `retried` marks the second try after a 491, which gets no
    /// third.
    ///
    /// RFC 3261 section 14.1 starts no INVITE in a dialog while another
    /// INVITE transaction of the dialog is in progress in either direction:
    /// one this user agent sent without its final response, or one it
    /// received that is not confirmed, as a 2xx that waits for its ACK. RFC
    /// 3264 section 4 starts no offer while one is outstanding, and the UA
    /// starts no re-INVITE without an offer then either. A re-INVITE also
    /// waits for one that got a 491 and waits to go again. In each case it
    /// is refused, with nothing sent.
    ///
    /// The request is built from the dialog (section 12.2.1.1), with the
    /// next CSeq number, which it keeps whatever happens to it. The replay
    /// context of its 2xx is set aside now, so that a 2xx is never left
    /// without its ACK for want of room. The session itself does not change
    /// until a 2xx comes.
    fn reinvite(
        &mut self,
        operation: Option<OperationId>,
        key: UsageKey,
        offer: Option<Description>,
        retried: bool,
    ) -> Result<(), Error> {
        let Some(usage) = self.usages.get(key) else {
            return Err(if self.ended(key).is_some() {
                Error::InvalidTransition
            } else {
                Error::StaleDecision
            });
        };
        let unconfirmed = self.replays.iter().any(|(_, replay)| {
            replay.usage == Some(key)
                && (replay.ack == AckObligation::AwaitingPeer
                    || replay.ack_body == AckBody::Preparing)
        });
        if usage.phase() != UsagePhase::Established
            || usage.bye != ByeIntent::None
            || usage.exchange.is_some()
            || usage.retry.is_some()
            || usage.negotiation != Negotiation::Stable
            || unconfirmed
        {
            return Err(Error::InvalidTransition);
        }
        let dialog = usage.dialog;
        if self.reinvites >= self.limits.reinvites || !self.reserve_replay() {
            return Err(Error::CapacityExceeded);
        }

        // A UAS that sent nothing in the dialog yet picks its first number
        // from this.
        let built =
            self.random.next_u64().ok_or(Error::Internal).and_then(|seed| {
                let record = self.dialogs.get_mut(dialog).expect("live");
                let outgoing = record
                    .request(Method::INVITE, Sequence::Next { seed })
                    .map_err(|error| match error {
                        // Out of numbers, the dialog takes no new request.
                        RequestError::CSeqExhausted => {
                            Error::InvalidTransition
                        }
                        RequestError::Terminated => Error::StaleDecision,
                        RequestError::WrongSequence
                        | RequestError::Cancel
                        | RequestError::Invalid => Error::Internal,
                    })?;
                let cseq = record.local_cseq().expect("just numbered");
                Ok((outgoing, cseq, record.id().clone()))
            });
        let (outgoing, cseq, id) = match built {
            Ok(built) => built,
            Err(error) => {
                self.replays.release();
                return Err(error);
            }
        };
        let sent = SentReinvite {
            usage: key,
            dialog: id,
            operation,
            offer,
            request: Some(Box::new(outgoing)),
            retried,
            reserved: true,
            incomplete: false,
            kept: None,
        };
        let has_offer = sent.offer.is_some();
        let Ok(exchange) =
            self.exchanges.insert(InviteExchange::reinvite(cseq, sent))
        else {
            self.replays.release();
            return Err(Error::CapacityExceeded);
        };

        self.reinvites += 1;
        let usage = self.usages.get_mut(key).expect("checked above");
        usage.exchange = Some(exchange);
        if has_offer {
            usage.negotiation.offer_sent(cseq).expect("checked stable");
        }
        self.effects.push(Effect::StartReinvite { exchange });
        Ok(())
    }

    /// Hands the runtime a re-INVITE to send, with where it goes and the
    /// offer it carries, if any.
    pub(crate) fn take_reinvite(
        &mut self,
        exchange: ExchangeKey,
    ) -> Option<(Outgoing, Option<Description>)> {
        let Scope::Reinvite(sent) =
            &mut self.exchanges.get_mut(exchange)?.scope
        else {
            return None;
        };
        let request = sent.request.take()?;
        Some((*request, sent.offer.clone()))
    }

    /// Records whether the core took a re-INVITE. One it did not take never
    /// started its transaction, and fails as a re-INVITE that got no 2xx,
    /// which leaves the session as it was (RFC 3261 section 14.1).
    pub(crate) fn reinvite_started(
        &mut self,
        key: ExchangeKey,
        result: Result<(), Error>,
        now: Instant,
    ) {
        let Some(InviteExchange { scope: Scope::Reinvite(sent), .. }) =
            self.exchanges.get(key)
        else {
            return;
        };

        match result {
            Ok(()) => {
                if let Some(operation) = sent.operation {
                    self.operations.advance(operation, Stage::Committed);
                }
            }
            Err(error) => {
                self.reinvite_failed(key, error, now);
                self.drop_reinvite(key);
            }
        }
    }

    /// Takes in a response to a re-INVITE this user agent sent.
    ///
    /// A provisional response changes nothing. It is unreliable, so it
    /// commits neither a new remote target ([RFC 6141 section 4.7] says it
    /// MUST NOT) nor a session description, and the 2xx has to carry the
    /// answer all the same (RFC 6337 section 3.1.1). A final response other
    /// than a 2xx fails the re-INVITE, see [`Model::reinvite_failed`].
    ///
    /// A 2xx must carry the dialog's identity. One with another To tag comes
    /// from another UA. It is not a fork, since a re-INVITE forms no dialog,
    /// and it is dropped without an ACK, which could only be built from a
    /// dialog. A copy of a 2xx gets the ACK again, as for the initial INVITE
    /// (section 14.1 makes the rules of the ACK the same).
    ///
    /// The first 2xx commits, apart from each other:
    ///
    /// * the remote target of its Contact, at once ([RFC 6141 section 4.7]),
    /// * the offer/answer exchange, at once with the answer to this user
    ///   agent's offer, or, for a late offer, once the answer to the 2xx's
    ///   offer is prepared for the ACK.
    ///
    /// The operation succeeds with the exchange. A 2xx without the answer or
    /// offer it owes fails it with [`Error::NegotiationFailure`], and the
    /// session ends with a BYE after the ACK, the policy of an initial
    /// INVITE. A 2xx that comes after the session ended still gets its ACK,
    /// which completes the INVITE transaction ([RFC 5407 section 3.2.3]).
    ///
    /// [RFC 6141 section 4.7]: https://www.rfc-editor.org/rfc/rfc6141.html#section-4.7
    /// [RFC 5407 section 3.2.3]: https://www.rfc-editor.org/rfc/rfc5407.html#section-3.2.3
    pub(crate) fn receive_reinvite_response<B>(
        &mut self,
        key: ExchangeKey,
        response: &Response<B>,
        description: Option<Description>,
        now: Instant,
    ) {
        let Some(exchange) = self.exchanges.get_mut(key) else {
            return;
        };
        let (pending, cseq) =
            (exchange.state() == ExchangeState::Pending, exchange.cseq);
        let Scope::Reinvite(sent) = &mut exchange.scope else {
            return;
        };
        let status = response.status();
        if !status.is_final() {
            return;
        }
        // A response without the dialog's identity is not the peer's,
        // whatever the core matched it to. A 481 or a 408 ends the session,
        // so that matters for an error response as well.
        if !sent.dialog.answered_by(cseq, response, status.is_success()) {
            sent.incomplete = true;
            return;
        }
        if !status.is_success() {
            if pending {
                self.reinvite_failed(key, Error::RemoteFailure(status), now);
            }
            return;
        }

        let replay = ReplayId {
            dialog: sent.dialog.clone(),
            cseq,
            direction: Direction::Outgoing,
        };
        if let Some(&context) = self.replay_index.get(&replay) {
            let context_record = self.replays.get(context).expect("indexed");
            if context_record.ack_body != AckBody::Preparing {
                self.effects.push(Effect::ResendAck { replay: context });
            }
            return;
        }
        // A 2xx after a failure of the transaction finds no room set aside.
        // It cannot come in signa-core, which delivers no response after the
        // failure it reports.
        if !std::mem::take(&mut sent.reserved) {
            return;
        }
        let (usage, kept, late) =
            (sent.usage, sent.kept.take(), sent.offer.is_none());
        let operation = sent.operation.take();
        exchange.final_received();

        let alive = self.usages.get(usage).is_some();
        let mut context =
            ReplayContext::new(replay.clone(), Source::Reinvite(key), usage);
        if !alive {
            context.usage_ended();
            context.dialog = kept;
        }
        let context = self.replays.insert_reserved(context);
        self.replay_index.insert(replay, context);
        self.let_go(usage, key);
        if let Some(operation) = operation {
            self.operations.advance(operation, Stage::Answered);
        }

        if !alive {
            // The session ended before the 2xx, and the operation with it.
            // The ACK still goes where the 2xx says, since a 2xx to a target
            // refresh replaces the remote target (RFC 6141 section 4.7), and
            // the ACK is built from the dialog after it (RFC 3261 section
            // 13.2.2.4). The dialog that builds it is the one the re-INVITE
            // kept, or the Mortal one in the table.
            let headers = response.headers();
            let replay_dialog =
                self.replays.get_mut(context).expect("just made");
            // A Contact that is not a SIP URI leaves the target as it was.
            let _ = match replay_dialog.dialog.as_deref_mut() {
                Some(dialog) => dialog.refresh_target(headers),
                None => match self
                    .dialog_index
                    .get(&replay_dialog.id.dialog)
                    .and_then(|&dialog| self.dialogs.get_mut(dialog))
                {
                    Some(dialog) => dialog.refresh_target(headers),
                    None => Ok(()),
                },
            };
            // An offer in the 2xx still owes its answer in the ACK, one that
            // rejects it, as for a fork the UA does not keep.
            match description.filter(|_| late) {
                Some(offer) => {
                    let record =
                        self.replays.get_mut(context).expect("just made");
                    record.ack_body = AckBody::Preparing;
                    self.effects.push(Effect::PrepareAnswer {
                        replay: context,
                        offer,
                        usage: None,
                    });
                }
                None => self.effects.push(Effect::SendAck { replay: context }),
            }
            return;
        }

        let dialog = self.usages.get(usage).expect("checked").dialog;
        if let Some(dialog) = self.dialogs.get_mut(dialog) {
            // A Contact that is not a SIP URI leaves the target as it was.
            let _ = dialog.refresh_target(response.headers());
        }
        let record = self.usages.get_mut(usage).expect("checked");
        match (record.negotiation, description) {
            (Negotiation::LocalOfferOutstanding { .. }, Some(answer))
                if record.negotiation.awaits_answer(cseq) =>
            {
                record
                    .negotiation
                    .answer_received(cseq)
                    .expect("checked to await it");
                record.remote = Some(answer);
                self.negotiated(usage);
                if let Some(operation) = operation {
                    self.complete(operation, Ok(Completion::Done));
                }
                self.effects.push(Effect::SendAck { replay: context });
            }
            (Negotiation::Stable, Some(offer)) if late => {
                record.negotiation.offer_received(cseq).expect("stable");
                record.remote = Some(offer.clone());
                // The operation completes with the answer.
                let replay = self.replays.get_mut(context).expect("just made");
                replay.operation = operation;
                replay.ack_body = AckBody::Preparing;
                self.effects.push(Effect::PrepareAnswer {
                    replay: context,
                    offer,
                    usage: Some(usage),
                });
            }
            _ => {
                self.fail_negotiation(usage);
                if let Some(operation) = operation {
                    self.complete(operation, Err(Error::NegotiationFailure));
                }
                self.effects.push(Effect::SendAck { replay: context });
            }
        }
    }

    /// Takes in the failure of a re-INVITE's transaction, such as a timeout
    /// with no response at all, while it has no final response.
    pub(crate) fn reinvite_transaction_failed(
        &mut self,
        key: ExchangeKey,
        error: Error,
        now: Instant,
    ) {
        let pending = self.exchanges.get(key).is_some_and(|exchange| {
            exchange.state() == ExchangeState::Pending
        });

        if pending {
            self.reinvite_failed(key, error, now);
        }
    }

    /// Records that the core dropped responses to a re-INVITE for want of
    /// room. If its final response is among them, the re-INVITE ends
    /// without one, see [`Model::reinvite_collection_finished`].
    pub(crate) fn reinvite_responses_lost(&mut self, key: ExchangeKey) {
        if let Some(InviteExchange { scope: Scope::Reinvite(sent), .. }) =
            self.exchanges.get_mut(key)
        {
            sent.incomplete = true;
        }
    }

    /// Records that the core finished collecting a re-INVITE's responses.
    /// Copies of its 2xx can no longer arrive, so the replay context goes.
    /// One that got no final response at all, as when the endpoint stopped
    /// or dropped it, fails, and leaves the session as it was.
    pub(crate) fn reinvite_collection_finished(
        &mut self,
        key: ExchangeKey,
        now: Instant,
    ) {
        let Some(InviteExchange { scope: Scope::Reinvite(sent), .. }) =
            self.exchanges.get(key)
        else {
            return;
        };

        let error = if sent.incomplete {
            Error::ObservationIncomplete
        } else {
            Error::DriverStopped
        };
        self.reinvite_transaction_failed(key, error, now);
        self.drop_reinvite(key);
    }

    /// Fails a re-INVITE that got a final response other than a 2xx, or
    /// none, with `error`.
    ///
    /// RFC 3261 section 14.1 has the session stay as it was, as if the
    /// re-INVITE had not been sent, so an offer it carried is withdrawn and
    /// the dialog has none outstanding. The remote target stays too, since
    /// only a 2xx or a reliable provisional response commits a new one (RFC
    /// 6141 section 4.7). Some failures go further:
    ///
    /// * A 491 says that the peer has a request of its own pending, and the
    ///   re-INVITE goes once more after a random wait, as section 14.1
    ///   recommends, unless it is already that second try.
    /// * A 481 says that the peer has no such dialog (RFC 5057 section 5.1).
    ///   The session ends, without a BYE, which would only get another 481.
    /// * A 408, or no response at all, ends the session with a BYE, as
    ///   sections 12.2.1.2 and 14.1 have a UAC terminate the dialog then.
    ///
    /// Any other failure, such as a 488 or a 500, fails the re-INVITE alone
    /// (RFC 5057 section 5.1).
    fn reinvite_failed(
        &mut self,
        key: ExchangeKey,
        error: Error,
        now: Instant,
    ) {
        let Some(exchange) = self.exchanges.get_mut(key) else {
            return;
        };
        exchange.final_received();
        let cseq = exchange.cseq;
        let Scope::Reinvite(sent) = &mut exchange.scope else {
            return;
        };
        let (usage, operation, offer, retried) = (
            sent.usage,
            sent.operation.take(),
            sent.offer.take(),
            sent.retried,
        );
        if std::mem::take(&mut sent.reserved) {
            self.replays.release();
        }
        self.let_go(usage, key);
        let Some(record) = self.usages.get_mut(usage) else {
            // The session ended first, which failed the operation then.
            return;
        };
        if record.negotiation.awaits_answer(cseq) {
            record.negotiation = Negotiation::Stable;
        }
        // A session that is ending takes no second try, so its operation
        // need not wait for one.
        let retry = !retried
            && record.phase() == UsagePhase::Established
            && record.bye == ByeIntent::None;

        let complete = |model: &mut Model<R>| {
            if let Some(operation) = operation {
                model.complete(operation, Err(error));
            }
        };
        match error {
            Error::RemoteFailure(status)
                if status.as_u16() == 491 && retry =>
            {
                self.schedule_retry(usage, operation, offer, now);
            }
            Error::RemoteFailure(status) if status.as_u16() == 481 => {
                complete(self);
                self.end_usage(usage, EndReason::ReinviteFailed(error));
            }
            Error::Timeout => self.end_failed_session(usage, error, complete),
            Error::RemoteFailure(status) if status.as_u16() == 408 => {
                self.end_failed_session(usage, error, complete);
            }
            _ => complete(self),
        }
    }

    /// Ends the session of a re-INVITE that timed out with a BYE, unless one
    /// is already asked for, and fails the operation.
    fn end_failed_session(
        &mut self,
        usage: UsageKey,
        error: Error,
        complete: impl FnOnce(&mut Model<R>),
    ) {
        complete(self);
        let bye = self.usages.get(usage).map(|usage| usage.bye);
        if bye == Some(ByeIntent::None) {
            let reason = EndReason::ReinviteFailed(error);
            self.start_bye(usage, None, reason, false);
        }
    }

    /// Has a re-INVITE that got a 491 go once more after a random wait
    /// (RFC 3261 section 14.1). The operation waits for that second try.
    fn schedule_retry(
        &mut self,
        usage: UsageKey,
        operation: Option<OperationId>,
        offer: Option<Description>,
        now: Instant,
    ) {
        let Some(random) = self.random.next_u64() else {
            if let Some(operation) = operation {
                let glare = StatusCode::from_u16(491).expect("a status");
                self.complete(operation, Err(Error::RemoteFailure(glare)));
            }
            return;
        };
        let record =
            self.usages.get_mut(usage).expect("checked by the caller");

        let owner = record.direction == Direction::Outgoing;
        let due = later(now, retry_delay(owner, random));
        let revision = record.revision;
        record.retry =
            Some(Box::new(Retry { operation, offer, due, revision }));
        self.timers.set(due, Timer::Retry(usage));
    }

    /// Sends a re-INVITE that got a 491 once more, if its change is still
    /// wanted, as RFC 3261 section 14.1 asks.
    ///
    /// The UA cannot know what the application wants now, so it goes by
    /// what changed. An offer/answer exchange that completed since the 491,
    /// such as the peer's re-INVITE that won the race, changed what the
    /// offer was made against, and a session that is ending or busy with
    /// another exchange takes none. The 491 then stands, and the operation
    /// fails with it, for the application to decide again. That is my
    /// policy.
    fn retry_due(&mut self, key: UsageKey) {
        let Some(usage) = self.usages.get_mut(key) else {
            return;
        };
        let Some(retry) = usage.retry.take() else {
            return;
        };
        let Retry { operation, offer, revision, .. } = *retry;
        let glare = StatusCode::from_u16(491).expect("a status");
        let glare = Error::RemoteFailure(glare);

        let result = if usage.revision == revision {
            self.reinvite(operation, key, offer, true)
        } else {
            Err(glare)
        };
        if let (Err(error), Some(operation)) = (result, operation) {
            let error = match error {
                Error::InvalidTransition => glare,
                error => error,
            };
            self.complete(operation, Err(error));
        }
    }

    /// Removes the record of a re-INVITE this user agent sent, once no more
    /// responses can arrive for it, with the replay context of its 2xx.
    fn drop_reinvite(&mut self, key: ExchangeKey) {
        let Some(exchange) = self.exchanges.remove(key) else {
            return;
        };
        self.reinvites -= 1;
        if let Scope::Reinvite(sent) = exchange.scope {
            if sent.reserved {
                self.replays.release();
            }
            self.let_go(sent.usage, key);
            debug_assert!(sent.operation.is_none(), "completed before");
        }

        let replays: Vec<ReplayKey> = self
            .replays
            .iter()
            .filter(|(_, replay)| replay.source == Source::Reinvite(key))
            .map(|(replay, _)| replay)
            .collect();
        for replay in replays {
            self.replays.get_mut(replay).expect("listed").duplicates_ended();
            self.reclaim_replay(replay);
        }
        self.effects.push(Effect::Released(Released::Exchange(key)));
    }

    /// Hands a dialog that leaves the dialog table to whatever still needs
    /// it to build an ACK, or drops it.
    ///
    /// An ACK that waits for its answer is owed all the same, and is built
    /// from the dialog once the answer is in, so the dialog goes to it, as
    /// to a cleanup. Failing that, a re-INVITE of the dialog without its
    /// final response may still get a 2xx, whose ACK the dialog builds (RFC
    /// 5407 section 3.2.3).
    fn hand_on(&mut self, dialog: Dialog) {
        let waiting = self.replays.iter_mut().find(|(_, replay)| {
            replay.id.dialog == *dialog.id()
                && replay.ack_body == AckBody::Preparing
                && replay.dialog.is_none()
        });
        let Some((_, replay)) = waiting else {
            self.keep_for_reinvite(dialog);
            return;
        };

        replay.dialog = Some(Box::new(dialog));
    }

    /// Hands a dialog to the re-INVITE it has without a final response, if
    /// any, so that a 2xx that comes late can still be acknowledged.
    fn keep_for_reinvite(&mut self, dialog: Dialog) {
        let pending = self.exchanges.iter_mut().find_map(|(_, exchange)| {
            let pending = exchange.state() == ExchangeState::Pending;
            match &mut exchange.scope {
                Scope::Reinvite(sent)
                    if pending && sent.dialog == *dialog.id() =>
                {
                    Some(sent)
                }
                _ => None,
            }
        });

        if let Some(sent) = pending {
            sent.kept = Some(Box::new(dialog));
        }
    }
}

/// Returns how long a re-INVITE that got a 491 waits before it goes once
/// more, from 64 random bits.
///
/// RFC 3261 section 14.1 picks it in units of 10 ms, from 2.1 to 4 seconds
/// for the UA that owns the dialog's Call-ID, which made it as the caller,
/// and from 0 to 2 seconds for the other. Their windows do not overlap, so
/// the two retries cannot collide again.
fn retry_delay(owner: bool, random: u64) -> Duration {
    let steps = if owner { 210 + random % 191 } else { random % 201 };
    Duration::from_millis(steps * 10)
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
        let target_revision =
            self.dialogs.get(usage.dialog).map_or(0, Dialog::target_revision);

        if mortal {
            if let Some(dialog) = self.dialogs.get_mut(usage.dialog) {
                dialog.terminate();
            }
        } else if let Some(dialog) = self.dialogs.remove(usage.dialog) {
            self.dialog_index.remove(dialog.id());
            self.hand_on(dialog);
        }
        // An INVITE exchange the usage held open ends with it. A re-INVITE
        // the peer sent gets a 487, which RFC 3261 section 15.1.2
        // recommends for a request a BYE leaves pending. One this user agent
        // sent fails, though its transaction goes on, and a 2xx it gets
        // still gets its ACK.
        if let Some(exchange) = usage.exchange {
            match self
                .exchanges
                .get_mut(exchange)
                .map(|record| &mut record.scope)
            {
                Some(Scope::Incoming { .. }) => {
                    self.withdraw(exchange, Withdrawal::Ended);
                }
                Some(Scope::Reinvite(sent)) => {
                    if let Some(operation) = sent.operation.take() {
                        self.complete(operation, Err(Error::SessionEnded));
                    }
                }
                Some(Scope::Outgoing) | None => {}
            }
        }
        if let Some(retry) = usage.retry {
            self.timers.cancel(retry.due, Timer::Retry(key));
            if let Some(operation) = retry.operation {
                self.complete(operation, Err(Error::SessionEnded));
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
        self.ended.push_back(Ended {
            usage: key,
            reason,
            negotiation: usage.negotiation,
            session_revision: usage.revision,
            target_revision,
        });
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
        let awaiting_ack = self.awaits_ack(key);
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

    /// Says whether an ACK holds back the BYE of a usage: the peer's ACK of
    /// a 2xx this user agent sent, which RFC 3261 section 15 has a callee
    /// wait for, or its own while the answer it carries is prepared.
    ///
    /// A UAS keeps a usage only once the 2xx of its initial INVITE is
    /// committed. The 2xx of a re-INVITE that the core has not taken yet
    /// counts too, since it may yet go out and wait for its ACK.
    fn awaits_ack(&self, key: UsageKey) -> bool {
        let pending_2xx = self
            .usages
            .get(key)
            .and_then(|usage| self.exchanges.get(usage.exchange?))
            .is_some_and(|exchange| {
                matches!(
                    exchange.state(),
                    ExchangeState::FinalSubmissionPending { status, .. }
                        if status.is_success()
                )
            });

        pending_2xx
            || self.replays.iter().any(|(_, replay)| {
                replay.usage == Some(key)
                    && (replay.ack == AckObligation::AwaitingPeer
                        || replay.ack_body == AckBody::Preparing)
            })
    }

    /// Lets a BYE that waited go, once nothing holds it back any more, as
    /// when the core refused the 2xx of a re-INVITE it waited for.
    fn release_bye(&mut self, key: UsageKey) {
        let Some(usage) = self.usages.get(key) else {
            return;
        };
        let ByeIntent::Deferred { operation, reason } = usage.bye else {
            return;
        };

        if !self.awaits_ack(key) {
            let restore = reason == EndReason::LocalBye;
            self.start_bye(key, operation, reason, restore);
        }
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
                self.hand_over(bye.operation);
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
        self.take_back(bye.operation);
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
            // An ACK may still need it, as for a re-INVITE that crossed the
            // BYE (RFC 5407 section 3.2.3).
            self.hand_on(dialog);
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
            reinvites: 4,
            t1: T1,
            t2: T2,
            decision_timeout: DECISION,
        }
    }

    impl UsageState {
        /// Returns the phase, the negotiation and the session description,
        /// which most tests compare.
        fn parts(self) -> (UsagePhase, Negotiation, Option<Description>) {
            (self.phase, self.negotiation, self.remote)
        }
    }

    /// Returns why a usage ended, and where its negotiation stood then.
    fn end_of(
        model: &Model<Counter>,
        usage: UsageKey,
    ) -> Option<(EndReason, Negotiation)> {
        model.ended(usage).map(|ended| (ended.reason, ended.negotiation))
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
        /// [`Model::take_effects`] calls it, so every test that takes the
        /// effects of an input checks it.
        pub(super) fn check(&self) {
            self.check_operations();
            self.check_reservations();
            self.check_timers();
            self.check_acks();

            let mut cleanups = 0;
            for (key, replay) in self.replays.iter() {
                assert_eq!(self.replay_index.get(&replay.id), Some(&key));
                assert_ne!(replay.retention(), Retention::Reclaimable);
                match replay.usage {
                    Some(usage) => {
                        assert_eq!(replay.bye, None);
                        // A re-INVITE goes either way in a dialog, so only
                        // the 2xx of an attempt says which way its usage
                        // went.
                        if let (Some(usage), Source::Attempt(_)) =
                            (self.usages.get(usage), replay.source)
                        {
                            assert_eq!(usage.direction, Direction::Outgoing);
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
                    scope:
                        Scope::Incoming {
                            kind:
                                Received::Initial { dialog: Some(dialog), .. },
                            ..
                        },
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
            let mut reinvites = 0;
            for (key, exchange) in self.exchanges.iter() {
                let open = matches!(
                    exchange.state(),
                    ExchangeState::Pending
                        | ExchangeState::FinalSubmissionPending { .. }
                );
                match &exchange.scope {
                    Scope::Incoming {
                        kind: Received::Initial { merge, .. },
                        ..
                    } => {
                        incoming += 1;
                        assert_eq!(self.merge_index.get(merge), Some(&key));
                    }
                    Scope::Incoming {
                        kind: Received::Reinvite { usage, .. },
                        ..
                    } => {
                        reinvites += 1;
                        if let (true, Some(usage)) =
                            (open, self.usages.get(*usage))
                        {
                            assert_eq!(usage.exchange, Some(key));
                        }
                    }
                    Scope::Reinvite(sent) => {
                        reinvites += 1;
                        let pending =
                            exchange.state() == ExchangeState::Pending;
                        if let (true, Some(usage)) =
                            (pending, self.usages.get(sent.usage))
                        {
                            assert_eq!(usage.exchange, Some(key));
                        }
                        if !pending {
                            assert!(
                                sent.operation.is_none() || !sent.reserved
                            );
                        }
                    }
                    Scope::Outgoing => {}
                }
                if let ExchangeState::FinalSubmissionPending {
                    operation: Some(operation),
                    ..
                } = exchange.state()
                {
                    let snapshot = self.operations.snapshot(operation);
                    assert_eq!(snapshot.unwrap().outcome, None);
                }
                if let Scope::Incoming {
                    decision_due,
                    expires_due,
                    provisional,
                    ..
                } = &exchange.scope
                {
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
            for (key, usage) in self.usages.iter() {
                timers += usize::from(usage.retry.is_some());
                if let Some(exchange) = usage.exchange {
                    let exchange = self.exchanges.get(exchange).unwrap();
                    assert_eq!(exchange.reinvite_usage(), Some(key));
                }
            }
            assert_eq!(self.merge_index.len(), incoming);
            assert_eq!(self.reinvites, reinvites);
            assert!(reinvites <= self.limits.reinvites);
            assert_eq!(self.timers.len(), timers);
        }

        /// Each operation without an outcome is held by exactly one record,
        /// or by the runtime, which reports its outcome. One that nothing
        /// holds would never end, and its waiter would wait for good. Each
        /// one a record holds is running, so that no record ends an
        /// operation twice or one that a reused slot now names.
        fn check_operations(&self) {
            let mut held: Vec<OperationId> = Vec::new();
            held.extend(self.commands.iter().map(|&(operation, _)| operation));
            for (_, exchange) in self.exchanges.iter() {
                if let ExchangeState::FinalSubmissionPending {
                    operation: Some(operation),
                    ..
                } = exchange.state()
                {
                    held.push(operation);
                }
                if let Scope::Reinvite(sent) = &exchange.scope {
                    held.extend(sent.operation);
                }
            }
            for (_, attempt) in self.attempts.iter() {
                held.extend(attempt.operation);
                if let CancelIntent::Waiting(Some(operation)) = attempt.cancel
                {
                    held.push(operation);
                }
            }
            for (_, usage) in self.usages.iter() {
                if let Some(retry) = &usage.retry {
                    held.extend(retry.operation);
                }
                if let ByeIntent::Deferred { operation, .. } = usage.bye {
                    held.extend(operation);
                }
            }
            held.extend(self.byes.values().filter_map(|bye| bye.operation));
            for (_, replay) in self.replays.iter() {
                held.extend(replay.operation);
            }
            held.extend(self.handed.iter().copied());

            for &operation in &held {
                let snapshot = self.operations.snapshot(operation);
                assert!(
                    snapshot
                        .is_some_and(|snapshot| snapshot.outcome.is_none()),
                    "{operation:?} is held but not running",
                );
            }
            for operation in self.operations.running() {
                let holders =
                    held.iter().filter(|&&held| held == operation).count();
                assert_eq!(holders, 1, "{operation:?} has {holders} holders");
            }
        }

        /// The slots set aside in each table are those of the records that
        /// hold a reservation. A 2xx under way to the core holds a dialog, a
        /// usage and a replay context for an initial INVITE, and a replay
        /// context for a re-INVITE. A re-INVITE this user agent sent holds a
        /// replay context until its first 2xx or its failure.
        fn check_reservations(&self) {
            let (mut sessions, mut replays) = (0, 0);
            for (_, exchange) in self.exchanges.iter() {
                let pending_2xx = matches!(
                    exchange.state(),
                    ExchangeState::FinalSubmissionPending { status, .. }
                        if status.is_success()
                );
                match (pending_2xx, exchange.reinvite_usage()) {
                    (true, Some(_)) => replays += 1,
                    (true, None) => sessions += 1,
                    (false, _) => {}
                }
                if matches!(&exchange.scope, Scope::Reinvite(sent) if sent.reserved)
                {
                    replays += 1;
                }
            }

            assert_eq!(self.dialogs.reserved(), sessions);
            assert_eq!(self.usages.reserved(), sessions);
            assert_eq!(self.replays.reserved(), sessions + replays);
        }

        /// Each timer that is set is due at the instant its record holds for
        /// it, so a timer outlives neither its record nor a change of the
        /// record's instant. `check` counts as many timers as the records
        /// hold instants, and each entry of the queue is a distinct record's,
        /// so no record holds an instant without its timer either.
        fn check_timers(&self) {
            for (at, timer) in self.timers.iter() {
                let held = match timer {
                    Timer::Decision(key) => match self.exchanges.get(key) {
                        Some(InviteExchange {
                            scope: Scope::Incoming { decision_due, .. },
                            ..
                        }) => *decision_due,
                        _ => None,
                    },
                    Timer::Expires(key) => match self.exchanges.get(key) {
                        Some(InviteExchange {
                            scope: Scope::Incoming { expires_due, .. },
                            ..
                        }) => *expires_due,
                        _ => None,
                    },
                    Timer::Provisional(key) => match self.exchanges.get(key) {
                        Some(InviteExchange {
                            scope:
                                Scope::Incoming {
                                    provisional: Some(provisional),
                                    ..
                                },
                            ..
                        }) => Some(provisional.due),
                        _ => None,
                    },
                    Timer::Retransmit(key) => self
                        .replays
                        .get(key)
                        .and_then(|replay| replay.retransmission?.next),
                    Timer::AckDeadline(key) => self
                        .replays
                        .get(key)
                        .and_then(|replay| replay.retransmission)
                        .map(|retransmission| retransmission.deadline),
                    Timer::Retry(key) => self
                        .usages
                        .get(key)
                        .and_then(|usage| Some(usage.retry.as_ref()?.due)),
                };
                assert_eq!(held, Some(at), "{timer:?} at {at:?}");
            }
        }

        /// Whatever still has to build an ACK or a BYE from a dialog can
        /// find it. The runtime builds the ACK of a [`Effect::SendAck`] and
        /// the BYE of a [`Effect::SendBye`] as it takes the effect, so the
        /// dialog has to be there when the input that made the effect ends.
        /// An ACK that waits for its answer is built when the answer comes,
        /// any number of inputs later, so its dialog has to last that long,
        /// in the table or in the context. So does that of a re-INVITE whose
        /// 2xx may still come after its session ended.
        fn check_acks(&self) {
            let can_build = |id: &DialogId, own: bool| {
                own || self.dialog_index.contains_key(id)
            };
            for effect in &self.effects {
                let (Effect::SendAck { replay } | Effect::SendBye { replay }) =
                    *effect
                else {
                    continue;
                };
                let Some(context) = self.replays.get(replay) else {
                    continue;
                };
                let bye = matches!(effect, Effect::SendBye { .. });
                assert!(
                    can_build(&context.id.dialog, context.dialog.is_some())
                        && (!bye || context.dialog.is_some()),
                    "{effect:?} for {context:?} cannot be built",
                );
            }
            for (_, replay) in self.replays.iter() {
                if replay.ack_body == AckBody::Preparing {
                    assert!(
                        can_build(&replay.id.dialog, replay.dialog.is_some()),
                        "{replay:?} waits for an answer to an ACK it cannot \
                         build",
                    );
                }
                if replay.bye == Some(Bye::Owed) {
                    assert!(replay.dialog.is_some(), "{replay:?} owes a BYE");
                }
            }
            for (_, exchange) in self.exchanges.iter() {
                let Scope::Reinvite(sent) = &exchange.scope else {
                    continue;
                };
                if exchange.state() == ExchangeState::Pending
                    && self.usages.get(sent.usage).is_none()
                {
                    assert!(
                        can_build(&sent.dialog, sent.kept.is_some()),
                        "{sent:?} may get a 2xx it cannot acknowledge",
                    );
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

        // The endpoint stopped, which leaves nothing of the exchange.
        model.final_refused(exchange, true);
        model.take_effects();
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

        let state = model.usage_state(usage).unwrap();
        assert_eq!(state.phase, UsagePhase::Established);
        assert_eq!(state.negotiation, Negotiation::Stable);
        assert_eq!(state.remote, Some(answer()));
        model.end_usage(usage, EndReason::LocalBye);
        let state = model.usage_state(usage).unwrap();
        assert_eq!(state.phase, UsagePhase::Ended);
        assert_eq!(state.remote, None, "an ended session keeps no SDP");
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
            end_of(&model, usage),
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
        let phase = model.usage_state(usage).unwrap().phase;
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
        let state = model.usage_state(usage).unwrap();
        assert_eq!(state.phase, UsagePhase::Ending);
        assert_eq!(
            state.negotiation,
            Negotiation::LocalOfferOutstanding { cseq: 314159 },
        );
        assert_eq!(state.remote, None);

        model.ack_written(acks(&effects)[0], true);
        let effects = model.take_effects();
        assert_eq!(session_byes(&effects, usage), 1);
        model.bye_started(usage, Ok(())).unwrap();
        model.check();
        assert_eq!(
            end_of(&model, usage),
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
            let state = model.usage_state(usage).unwrap();
            (state.negotiation, state.remote)
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
        let phase = model.usage_state(third).unwrap().phase;
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
        assert_eq!(model.reinvite_session(exchange), None, "an initial one");

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
        assert_eq!(end_of(&model, usage), Some((reason, Negotiation::Stable)));
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
        assert_eq!(
            model.usage_state(early).unwrap().phase,
            UsagePhase::Ending
        );

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
        assert_eq!(
            model.usage_state(usage).unwrap().phase,
            UsagePhase::Ending
        );
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
        assert_eq!(
            model.usage_state(session).unwrap().phase,
            UsagePhase::Ending
        );
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
        let state = model.usage_state(session).unwrap();
        assert_eq!(state.phase, UsagePhase::Ended, "nothing comes back");

        let mut model = self::model(limits());
        let (_, session, _) = caller_session(&mut model);
        let terminate = run(&mut model, Command::Terminate { usage: session });
        let refused = Error::CoreSubmissionRejected;
        assert!(model.bye_started(session, Err(refused)).is_none());
        model.check();
        assert_eq!(model.take_outcome(terminate), Some(Err(refused)));
        assert_eq!(
            model.usage_state(session).unwrap().phase,
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

        assert_eq!(end_of(&model, ended[0]), None, "the oldest went");
        for &session in &ended[1..] {
            let (reason, _) = end_of(&model, session).unwrap();
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
            model.usage_state(usage).map(UsageState::parts),
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
            model.usage_state(usage).map(UsageState::parts),
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
        assert_eq!(
            model.usage_state(usage).unwrap().negotiation,
            Negotiation::Stable
        );
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
            model.usage_state(usage).map(UsageState::parts),
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
            model.usage_state(sessions[0]).unwrap().remote,
            Some(preview.clone())
        );
        assert_eq!(
            model.usage_state(sessions[1]).unwrap().remote,
            Some(preview)
        );
        assert!(!sessions.iter().any(|&usage| {
            model.usage_state(usage).unwrap().remote == Some(changed.clone())
        }));
        assert!(sessions.iter().all(|&usage| {
            model.usage_state(usage).unwrap().negotiation
                == Negotiation::Stable
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
            model.usage_state(sessions[1]).unwrap().negotiation,
            Negotiation::RemoteOfferOutstanding { cseq: 314159 },
        );

        model.answer_prepared(replays[1], None);
        model.check();
        let effects = model.take_effects();
        assert_eq!(failures(&effects), [sessions[1]]);
        assert_eq!(model.usage_state(sessions[0]).unwrap().negotiation, {
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
            end_of(&model, usage).unwrap().0,
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
        assert_eq!(
            model.usage_state(usage).unwrap().phase,
            UsagePhase::Ending
        );

        model.answer_prepared(replay, Some(answer()));
        model.ack_written(replay, true);
        model.check();

        assert_eq!(session_byes(&model.take_effects(), usage), 1);
        model.bye_started(usage, Ok(())).unwrap();
        assert_eq!(end_of(&model, usage).unwrap().0, EndReason::LocalBye);
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
            end_of(&model, usage).unwrap().0,
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
            assert_eq!(end_of(&model, usage).unwrap().0, reason);
        }
    }

    /// A response of the callee of [`caller_session`] to a re-INVITE
    /// numbered `cseq`, with `tag` on its To and `contact` as its Contact.
    fn to_reinvite(
        status: &str,
        tag: &str,
        contact: &str,
        cseq: u32,
    ) -> Response<Bytes> {
        let text = String::from_utf8(
            reply(status, tag, contact, "").to_bytes().to_vec(),
        )
        .unwrap();
        response(
            &text
                .replace("\r\n", "\n")
                .replace("314159 INVITE", &format!("{cseq} INVITE")),
        )
    }

    /// Returns the re-INVITE that `effects` start.
    fn started(effects: &[Effect]) -> ExchangeKey {
        effects
            .iter()
            .find_map(|effect| match effect {
                Effect::StartReinvite { exchange } => Some(*exchange),
                _ => None,
            })
            .expect("a re-INVITE starts")
    }

    /// Has the caller of [`caller_session`] send a re-INVITE with `offer`,
    /// which the core takes, and returns the operation, the exchange and
    /// its CSeq number.
    fn reinvited(
        model: &mut Model<Counter>,
        usage: UsageKey,
        offer: Option<Description>,
        now: Instant,
    ) -> (OperationId, ExchangeKey, u32) {
        let operation = run(model, Command::Reinvite { usage, offer });
        let exchange = started(&model.take_effects());
        let (outgoing, _) = model.take_reinvite(exchange).unwrap();
        let (cseq, method) =
            protocol::cseq(outgoing.request.headers()).unwrap();
        assert_eq!(method, "INVITE");
        model.reinvite_started(exchange, Ok(()), now);
        model.check();
        (operation, exchange, cseq)
    }

    /// The UAS of [`accepted`] with the ACK of its 2xx in, whose session is
    /// established and settled.
    fn acknowledged(model: &mut Model<Counter>, clock: &Clock) -> UsageKey {
        let (_, _, usage) = accepted(model, clock);
        model.receive_ack(&uas_dialog(), 314159, None);
        model.check();
        model.take_effects();
        usage
    }

    /// A re-INVITE the caller sends to the UAS of [`accepted`], numbered
    /// `cseq`, with `contact` as its Contact.
    fn reinvite_from_caller(cseq: u32, contact: &str) -> Request<Bytes> {
        let text =
            String::from_utf8(from_caller("INVITE", cseq).to_bytes().to_vec())
                .unwrap();
        request(
            &text
                .replace("\r\n", "\n")
                .replace("<sip:alice@192.0.2.1>", &format!("<{contact}>")),
        )
    }

    fn outcome(
        model: &Model<Counter>,
        operation: OperationId,
    ) -> Option<Result<Completion, Error>> {
        model.operations.snapshot(operation).unwrap().outcome
    }

    fn status(code: u16) -> StatusCode {
        StatusCode::from_u16(code).unwrap()
    }

    /// A re-INVITE that a 2xx answers moves the session to its next
    /// revision, with the answer as what the peer sent, and replaces the
    /// remote target with the 2xx's Contact (RFC 3261 sections 12.2.1.2 and
    /// 14.1). The ACK takes the re-INVITE's number, and the operation
    /// succeeds once the exchange is complete.
    #[test]
    fn reinvite_success_updates_session_revision() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let before = model.usage_state(usage).unwrap();
        assert_eq!((before.session_revision, before.target_revision), (1, 0));

        let offer = description("v=0 hold");
        let (operation, exchange, cseq) =
            reinvited(&mut model, usage, Some(offer), clock.now());
        assert_eq!(cseq, 314160, "the next number after the INVITE's");
        let state = model.usage_state(usage).unwrap();
        assert_eq!(
            state.negotiation,
            Negotiation::LocalOfferOutstanding { cseq }
        );
        assert_eq!(state.session_revision, 1, "nothing changes before");

        let answer = description("v=0 held");
        let ok = to_reinvite("200 OK", "callee", "sip:bob@192.0.2.40", cseq);
        model.receive_reinvite_response(
            exchange,
            &ok,
            Some(answer.clone()),
            clock.now(),
        );
        model.check();
        let effects = model.take_effects();

        assert_eq!(notices(&effects), [Event::NegotiationCompleted { usage }]);
        assert_eq!(outcome(&model, operation), Some(Ok(Completion::Done)));
        let state = model.usage_state(usage).unwrap();
        assert_eq!(state.negotiation, Negotiation::Stable);
        assert_eq!(state.remote, Some(answer));
        assert_eq!((state.session_revision, state.target_revision), (2, 1));
        let dialog = model.usages.get(usage).unwrap().dialog;
        let dialog = model.dialogs.get(dialog).unwrap();
        assert_eq!(dialog.target().uri(), "sip:bob@192.0.2.40");
        let ack = acks(&effects)[0];
        let (ack, _) = model.ack_request(ack).unwrap();
        assert_eq!(
            protocol::cseq(ack.request.headers()).unwrap(),
            (cseq, "ACK")
        );
        assert_eq!(ack.request.uri().as_str(), "sip:bob@192.0.2.40");
    }

    /// A non-2xx to a re-INVITE leaves the session as it was, as if the
    /// re-INVITE had not been sent (RFC 3261 section 14.1). Its offer is
    /// withdrawn, and neither the description, the revisions nor the target
    /// change. No BYE goes, and the UA sends no ACK, which is the core's for
    /// a non-2xx. The same goes for a re-INVITE the application rejects as
    /// a UAS, which only records its CSeq.
    #[test]
    fn reinvite_rejection_preserves_existing_session() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let before = model.usage_state(usage).unwrap();

        let video = Some(description("v=0 video"));
        let (operation, exchange, cseq) =
            reinvited(&mut model, usage, video, clock.now());
        let refused = to_reinvite(
            "488 Not Acceptable Here",
            "callee",
            "sip:bob@192.0.2.40",
            cseq,
        );
        model.receive_reinvite_response(exchange, &refused, None, clock.now());
        model.check();

        assert_eq!(
            model.take_effects(),
            [Effect::OperationEnded { operation }],
        );
        let rejected = Error::RemoteFailure(status(488));
        assert_eq!(outcome(&model, operation), Some(Err(rejected)));
        assert_eq!(model.usage_state(usage).unwrap(), before);
        assert_eq!(model.usages.get(usage).unwrap().exchange, None);
        let next = run(
            &mut model,
            Command::Reinvite { usage, offer: Some(description("v=0")) },
        );
        assert_eq!(outcome(&model, next), None, "a new one may go");

        let mut model = self::model(limits());
        let usage = acknowledged(&mut model, &clock);
        let before = model.usage_state(usage).unwrap();
        let authority = model
            .receive_invite(
                &reinvite_from_caller(314160, "sip:alice@192.0.2.9"),
                offer(),
                clock.now(),
            )
            .unwrap();
        let exchange = authority.exchange;
        model
            .try_submit(Command::Reject { authority, status: status(488) })
            .unwrap();
        model.run_commands();
        assert_eq!(finals(model.take_effects()), [(exchange, 488)]);
        model.final_committed(exchange, clock.now());
        model.check();

        let effects = model.take_effects();
        assert!(
            effects.contains(&Effect::Released(Released::Exchange(exchange)))
        );
        assert!(notices(&effects).is_empty() && statuses(&effects).is_empty());
        assert_eq!(model.usage_state(usage).unwrap(), before);
        let dialog = model.usages.get(usage).unwrap().dialog;
        let dialog = model.dialogs.get(dialog).unwrap();
        assert_eq!(dialog.target().uri(), "sip:alice@192.0.2.1");
        assert_eq!(dialog.remote_cseq(), Some(314160), "the CSeq is taken");
    }

    /// A CANCEL of a re-INVITE that has no final yet gets it a 487, and the
    /// session goes on as it was (RFC 3261 sections 9.2 and 14.1). The 200 to
    /// the CANCEL carries the dialog's tag. The application's accept after
    /// that finds the final taken, and the dialog takes a new re-INVITE.
    #[test]
    fn reinvite_cancel_preserves_existing_usage_when_required() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let usage = acknowledged(&mut model, &clock);
        let before = model.usage_state(usage).unwrap();
        let authority = model
            .receive_invite(
                &reinvite_from_caller(314160, "sip:alice@192.0.2.9"),
                offer(),
                clock.now(),
            )
            .unwrap();
        let exchange = authority.exchange;
        assert_eq!(model.reinvite_session(exchange), Some(usage));

        let tag = model.receive_cancel(exchange).unwrap();
        assert_eq!(&tag, uas_dialog().local_tag());
        let effects = model.take_effects();
        assert_eq!(statuses(&effects), [487]);
        assert_eq!(notices(&effects), [Event::InviteWithdrawn { exchange }]);
        let late =
            run(&mut model, Command::Accept { authority, answer: answer() });
        assert_eq!(outcome(&model, late), Some(Err(Error::AlreadyFinalized)));
        model.final_committed(exchange, clock.now());
        model.check();

        let effects = model.take_effects();
        assert!(
            effects.contains(&Effect::Released(Released::Exchange(exchange)))
        );
        assert!(notices(&effects).is_empty() && statuses(&effects).is_empty());
        assert_eq!(model.usage_state(usage).unwrap(), before);
        assert_eq!(model.replays.len(), 0);
        assert!(
            model
                .receive_invite(
                    &reinvite_from_caller(314161, "sip:alice@192.0.2.1"),
                    offer(),
                    clock.now(),
                )
                .is_ok()
        );
    }

    /// RFC 3261 section 14.1 waits after a 491 for 2.1 to 4 seconds when
    /// this user agent owns the Call-ID, and up to 2 seconds when it does
    /// not, in units of 10 ms.
    #[test]
    fn glare_491_uses_correct_owner_dependent_window() {
        let ms = Duration::from_millis;
        assert_eq!(retry_delay(true, 0), ms(2100));
        assert_eq!(retry_delay(true, 190), ms(4000));
        assert_eq!(retry_delay(true, 191), ms(2100));
        assert_eq!(
            retry_delay(true, u64::MAX),
            ms(2100 + (u64::MAX % 191) * 10)
        );
        assert_eq!(retry_delay(false, 0), ms(0));
        assert_eq!(retry_delay(false, 200), ms(2000));
        assert_eq!(retry_delay(false, 201), ms(0));
        for random in 0..1000 {
            let owner = retry_delay(true, random);
            let other = retry_delay(false, random);
            assert!(ms(2100) <= owner && owner <= ms(4000));
            assert!(other <= ms(2000));
            assert_eq!(owner.as_millis() % 10, 0);
            assert_eq!(other.as_millis() % 10, 0);
        }

        // The caller made the Call-ID, so it owns it.
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let (_, exchange, cseq) =
            reinvited(&mut model, usage, Some(answer()), clock.now());
        let glare =
            to_reinvite("491 Request Pending", "callee", "sip:b@h", cseq);
        model.receive_reinvite_response(exchange, &glare, None, clock.now());
        model.check();
        let wait = model.next_deadline().unwrap() - clock.now();
        assert!(ms(2100) <= wait && wait <= ms(4000), "{wait:?}");

        // The callee did not.
        let mut model = self::model(limits());
        let usage = acknowledged(&mut model, &clock);
        let operation = run(
            &mut model,
            Command::Reinvite { usage, offer: Some(answer()) },
        );
        let exchange = started(&model.take_effects());
        let (outgoing, _) = model.take_reinvite(exchange).unwrap();
        let (cseq, _) = protocol::cseq(outgoing.request.headers()).unwrap();
        model.reinvite_started(exchange, Ok(()), clock.now());
        let glare = response(&format!(
            "SIP/2.0 491 Request Pending
Via: SIP/2.0/UDP 192.0.2.4;branch=z9hG4bKreinvite
To: <sip:alice@atlanta.example.com>;tag=1928301774
From: <sip:bob@biloxi.example.com>;tag=0000000000000001
Call-ID: a84b4c76e66710@pc33.atlanta.example.com
CSeq: {cseq} INVITE

"
        ));
        model.receive_reinvite_response(exchange, &glare, None, clock.now());
        model.check();
        assert_eq!(outcome(&model, operation), None, "it waits to go again");
        let wait = model.next_deadline().unwrap() - clock.now();
        assert!(wait <= ms(2000), "{wait:?}");
    }

    /// A re-INVITE that arrives while this user agent has not answered the
    /// last one gets a 500 with a Retry-After of 0 to 10 seconds, and one
    /// while this user agent's own re-INVITE waits for its final a 491 (RFC
    /// 3261 section 14.2). A re-INVITE in the early dialog of an INVITE not
    /// yet answered gets the 500 too. None of them changes the dialog.
    #[test]
    fn overlapping_incoming_invite_uses_500_retry_after() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let usage = acknowledged(&mut model, &clock);
        model
            .receive_invite(
                &reinvite_from_caller(314160, "sip:alice@192.0.2.1"),
                offer(),
                clock.now(),
            )
            .unwrap();
        let second = model.receive_invite(
            &reinvite_from_caller(314161, "sip:alice@192.0.2.1"),
            offer(),
            clock.now(),
        );
        model.check();

        let Err(refusal @ Refusal::Overlapping(seconds)) = second else {
            panic!("not refused as overlapping: {second:?}");
        };
        assert!(seconds <= 10);
        assert_eq!(refusal.status().as_u16(), 500);
        let dialog = model.usages.get(usage).unwrap().dialog;
        assert_eq!(
            model.dialogs.get(dialog).unwrap().remote_cseq(),
            Some(314160),
            "a refused request records nothing",
        );

        let mut model = self::model(limits());
        model.receive_invite(&request(INVITE), offer(), clock.now()).unwrap();
        assert!(matches!(
            model.receive_invite(
                &reinvite_from_caller(314160, "sip:alice@192.0.2.1"),
                offer(),
                clock.now(),
            ),
            Err(Refusal::Overlapping(_)),
        ));

        let mut model = self::model(limits());
        let (_, usage, _) = caller_session(&mut model);
        reinvited(&mut model, usage, Some(answer()), clock.now());
        let crossing = from_callee("INVITE", "callee", 1);
        let refusal =
            model.receive_invite(&crossing, offer(), clock.now()).unwrap_err();
        assert_eq!(refusal, Refusal::RequestPending);
        assert_eq!(refusal.status().as_u16(), 491);
        model.check();
    }

    /// The re-INVITE that goes again after a 491 is a new request, with the
    /// next CSeq number and a transaction of its own (RFC 3261 section
    /// 14.1). It goes once. A 491 to it fails the operation. So does an
    /// exchange that completed meanwhile, such as the peer's re-INVITE that
    /// won, since the offer was made against the session before it.
    #[test]
    fn glare_retry_allocates_new_cseq_and_transaction() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let hold = description("v=0 hold");
        let (operation, first, cseq) =
            reinvited(&mut model, usage, Some(hold.clone()), clock.now());
        let glare = |cseq| {
            to_reinvite("491 Request Pending", "callee", "sip:b@h", cseq)
        };
        model.receive_reinvite_response(
            first,
            &glare(cseq),
            None,
            clock.now(),
        );
        assert_eq!(
            model.usage_state(usage).unwrap().negotiation,
            Negotiation::Stable,
            "the offer is withdrawn meanwhile",
        );

        let due = model.next_deadline().unwrap();
        let effects = advance_to(&mut model, &mut clock, due);
        let second = started(&effects);
        assert_ne!(second, first);
        let (outgoing, carried) = model.take_reinvite(second).unwrap();
        assert_eq!(
            protocol::cseq(outgoing.request.headers()).unwrap(),
            (cseq + 1, "INVITE"),
        );
        assert_eq!(carried, Some(hold));
        model.reinvite_started(second, Ok(()), clock.now());
        model.receive_reinvite_response(
            second,
            &glare(cseq + 1),
            None,
            clock.now(),
        );
        model.check();
        let glare_error = Error::RemoteFailure(status(491));
        assert_eq!(outcome(&model, operation), Some(Err(glare_error)));
        assert_eq!(model.next_deadline(), None, "no third try");
        model.reinvite_collection_finished(first, clock.now());
        model.reinvite_collection_finished(second, clock.now());
        model.check();
        assert_eq!(model.reinvites, 0);

        // The callee's re-INVITE completes before the retry is due.
        let mut model = self::model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let (operation, first, cseq) =
            reinvited(&mut model, usage, Some(answer()), clock.now());
        model.receive_reinvite_response(
            first,
            &glare(cseq),
            None,
            clock.now(),
        );
        let authority = model
            .receive_invite(
                &from_callee("INVITE", "callee", 2),
                offer(),
                clock.now(),
            )
            .unwrap();
        let exchange = authority.exchange;
        run(&mut model, Command::Accept { authority, answer: answer() });
        model.final_committed(exchange, clock.now());
        let id = model.replays.iter().next().map(|(_, r)| r.id.clone());
        let id = id.unwrap();
        model.receive_ack(&id.dialog, 2, None);
        model.take_effects();
        let due = model.next_deadline().unwrap();
        let effects = advance_to(&mut model, &mut clock, due);

        assert!(
            !effects
                .iter()
                .any(|effect| matches!(effect, Effect::StartReinvite { .. }))
        );
        assert_eq!(outcome(&model, operation), Some(Err(glare_error)));
    }

    /// The 2xx of a re-INVITE commits its new remote target at once, apart
    /// from the session description (RFC 6141 sections 4.3 and 4.6). A
    /// re-INVITE without an offer gets the UAS's offer in the 2xx and the
    /// answer in the ACK, so the target moves at the 2xx and the session at
    /// the ACK. An ACK without the answer fails the exchange and ends the
    /// session, and the target stays where the 2xx moved it.
    #[test]
    fn target_refresh_commit_is_separate_from_media_commit() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let usage = acknowledged(&mut model, &clock);
        let authority = model
            .receive_invite(
                &reinvite_from_caller(314160, "sip:alice@192.0.2.9"),
                Ok(Body::Empty),
                clock.now(),
            )
            .unwrap();
        let exchange = authority.exchange;
        let dialog = model.usages.get(usage).unwrap().dialog;
        let target = |model: &Model<Counter>| {
            model.dialogs.get(dialog).unwrap().target().uri().to_owned()
        };
        assert_eq!(
            target(&model),
            "sip:alice@192.0.2.1",
            "not before the 2xx"
        );

        let accept =
            run(&mut model, Command::Accept { authority, answer: answer() });
        model.final_committed(exchange, clock.now());
        model.check();
        let effects = model.take_effects();
        assert!(notices(&effects).is_empty());
        assert_eq!(
            outcome(&model, accept),
            Some(Ok(Completion::Session(usage)))
        );
        let state = model.usage_state(usage).unwrap();
        assert_eq!(target(&model), "sip:alice@192.0.2.9");
        assert_eq!((state.session_revision, state.target_revision), (1, 1));
        assert_eq!(
            state.negotiation,
            Negotiation::LocalOfferOutstanding { cseq: 314160 },
        );

        model.receive_ack(&uas_dialog(), 314160, Some(description("v=0 ok")));
        model.check();
        assert_eq!(
            notices(&model.take_effects()),
            [Event::NegotiationCompleted { usage }],
        );
        let state = model.usage_state(usage).unwrap();
        assert_eq!((state.session_revision, state.target_revision), (2, 1));

        // An ACK without the answer.
        let authority = model
            .receive_invite(
                &reinvite_from_caller(314161, "sip:alice@192.0.2.10"),
                Ok(Body::Empty),
                clock.now(),
            )
            .unwrap();
        let exchange = authority.exchange;
        run(&mut model, Command::Accept { authority, answer: answer() });
        model.final_committed(exchange, clock.now());
        model.take_effects();
        model.receive_ack(&uas_dialog(), 314161, None);
        model.check();
        let effects = model.take_effects();
        assert!(
            notices(&effects).contains(&Event::NegotiationFailed { usage })
        );
        assert_eq!(session_byes(&effects, usage), 1);
        assert_eq!(target(&model), "sip:alice@192.0.2.10", "the target stays");
        assert_eq!(model.usage_state(usage).unwrap().session_revision, 2);
    }

    /// An unreliable provisional response to a re-INVITE refreshes nothing,
    /// whatever its Contact says (RFC 6141 section 4.7), and an error
    /// response that follows it refreshes nothing either.
    #[test]
    fn unreliable_provisional_cannot_commit_remote_target_refresh() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let (operation, exchange, cseq) =
            reinvited(&mut model, usage, Some(answer()), clock.now());
        let dialog = model.usages.get(usage).unwrap().dialog;

        for status in ["180 Ringing", "183 Session Progress"] {
            let ringing =
                to_reinvite(status, "callee", "sip:bob@192.0.2.77", cseq);
            model.receive_reinvite_response(
                exchange,
                &ringing,
                Some(description("v=0 early")),
                clock.now(),
            );
        }
        model.check();
        assert!(model.take_effects().is_empty());
        assert_eq!(
            model.dialogs.get(dialog).unwrap().target().uri(),
            "sip:bob@192.0.2.4"
        );
        assert_eq!(outcome(&model, operation), None);
        assert_eq!(model.usage_state(usage).unwrap().remote, Some(answer()));

        let busy =
            to_reinvite("486 Busy Here", "callee", "sip:bob@192.0.2.77", cseq);
        model.receive_reinvite_response(exchange, &busy, None, clock.now());
        let state = model.usage_state(usage).unwrap();
        assert_eq!(
            model.dialogs.get(dialog).unwrap().target().uri(),
            "sip:bob@192.0.2.4"
        );
        assert_eq!(state.target_revision, 0);
    }

    /// A new re-INVITE may go as soon as the last one has its final response
    /// and its ACK. The replay contexts of earlier 2xx responses, which stay
    /// until the core stops collecting their responses (Timer M) or keeps
    /// the transaction in Accepted (Timer L), hold nothing up, on either
    /// side.
    #[test]
    fn new_reinvite_after_ack_does_not_wait_for_timer_m_or_l_cleanup() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, usage, initial) = caller_session(&mut model);
        assert!(model.has_replay(initial), "the INVITE's 2xx may come again");

        let (first_op, first, cseq) =
            reinvited(&mut model, usage, Some(answer()), clock.now());
        let ok = to_reinvite("200 OK", "callee", "sip:bob@192.0.2.4", cseq);
        model.receive_reinvite_response(
            first,
            &ok,
            Some(answer()),
            clock.now(),
        );
        let ack = acks(&model.take_effects())[0];
        model.ack_written(ack, true);
        assert_eq!(outcome(&model, first_op), Some(Ok(Completion::Done)));
        assert!(model.has_replay(ack), "the re-INVITE's 2xx may come again");

        let (second_op, second, cseq) =
            reinvited(&mut model, usage, Some(answer()), clock.now());
        assert_eq!(cseq, 314161);
        let ok = to_reinvite("200 OK", "callee", "sip:bob@192.0.2.4", cseq);
        model.receive_reinvite_response(
            second,
            &ok,
            Some(answer()),
            clock.now(),
        );
        model.check();
        assert_eq!(outcome(&model, second_op), Some(Ok(Completion::Done)));

        // As a UAS, the next re-INVITE may come once the ACK came, while
        // the core still keeps the last one in Accepted.
        let mut model = self::model(limits());
        acknowledged(&mut model, &clock);
        let authority = model
            .receive_invite(
                &reinvite_from_caller(314160, "sip:alice@192.0.2.1"),
                offer(),
                clock.now(),
            )
            .unwrap();
        let exchange = authority.exchange;
        run(&mut model, Command::Accept { authority, answer: answer() });
        model.final_committed(exchange, clock.now());
        let early = model.receive_invite(
            &reinvite_from_caller(314161, "sip:alice@192.0.2.1"),
            offer(),
            clock.now(),
        );
        assert!(early.is_ok(), "a 2xx that awaits its ACK holds none up");
        model.check();
    }

    /// A copy of the 2xx of an older re-INVITE gets that re-INVITE's ACK,
    /// with the answer it carried, after a newer re-INVITE settled the
    /// session again (RFC 3261 sections 13.2.2.4 and 14.1).
    #[test]
    fn old_reinvite_duplicate_2xx_uses_old_ack_body() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, usage, _) = caller_session(&mut model);

        let (late_op, late, late_cseq) =
            reinvited(&mut model, usage, None, clock.now());
        let offer = description("v=0 their offer");
        let ok =
            to_reinvite("200 OK", "callee", "sip:bob@192.0.2.4", late_cseq);
        model.receive_reinvite_response(
            late,
            &ok,
            Some(offer.clone()),
            clock.now(),
        );
        let effects = model.take_effects();
        let replay = match &effects[..] {
            [
                Effect::PrepareAnswer {
                    replay,
                    offer: asked,
                    usage: Some(of),
                },
            ] if *asked == offer && *of == usage => *replay,
            other => panic!("no answer asked for: {other:?}"),
        };
        assert_eq!(outcome(&model, late_op), None, "it waits for the answer");
        let first_answer = description("v=0 first answer");
        model.answer_prepared(replay, Some(first_answer.clone()));
        let effects = model.take_effects();
        assert_eq!(acks(&effects), [replay]);
        model.ack_written(replay, true);
        assert_eq!(outcome(&model, late_op), Some(Ok(Completion::Done)));
        assert_eq!(model.usage_state(usage).unwrap().session_revision, 2);

        let (_, early, cseq) = reinvited(
            &mut model,
            usage,
            Some(description("v=0 next")),
            clock.now(),
        );
        let next = to_reinvite("200 OK", "callee", "sip:bob@192.0.2.4", cseq);
        model.receive_reinvite_response(
            early,
            &next,
            Some(answer()),
            clock.now(),
        );
        model.take_effects();
        model.receive_reinvite_response(late, &ok, Some(offer), clock.now());
        model.check();

        assert_eq!(model.take_effects(), [Effect::ResendAck { replay }]);
        let (ack, body) = model.ack_request(replay).unwrap();
        assert_eq!(body, Some(first_answer));
        assert_eq!(
            protocol::cseq(ack.request.headers()).unwrap(),
            (late_cseq, "ACK"),
        );
        assert_eq!(model.usage_state(usage).unwrap().session_revision, 3);
    }

    /// A 2xx to a re-INVITE with another To tag is not a fork. A re-INVITE
    /// forms no dialog, so it confirms nothing, gets no ACK, and settles
    /// nothing. The 2xx of the dialog's own peer does.
    #[test]
    fn unexpected_reinvite_to_tag_is_not_a_new_fork() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let (operation, exchange, cseq) =
            reinvited(&mut model, usage, Some(answer()), clock.now());
        let dialogs = model.dialogs.len();

        let stranger =
            to_reinvite("200 OK", "stranger", "sip:eve@192.0.2.66", cseq);
        model.receive_reinvite_response(
            exchange,
            &stranger,
            Some(answer()),
            clock.now(),
        );
        model.check();
        assert!(model.take_effects().is_empty());
        assert_eq!(model.dialogs.len(), dialogs);
        assert_eq!(outcome(&model, operation), None);

        let ok = to_reinvite("200 OK", "callee", "sip:bob@192.0.2.4", cseq);
        model.receive_reinvite_response(
            exchange,
            &ok,
            Some(answer()),
            clock.now(),
        );
        let effects = model.take_effects();
        assert!(confirmations(&effects).is_empty());
        assert_eq!(acks(&effects).len(), 1);
        assert_eq!(outcome(&model, operation), Some(Ok(Completion::Done)));
    }

    /// A BYE that ends a session while a re-INVITE is open ends it once,
    /// whichever side sent either.
    ///
    /// * The peer's BYE during its own re-INVITE that the application has
    ///   not decided gets that re-INVITE a 487 (RFC 3261 section 15.1.2).
    /// * This user agent's BYE during its own re-INVITE fails the
    ///   operation, and a 2xx that comes after it still gets its ACK, built
    ///   from the Mortal dialog (RFC 5407 section 3.2.3), and changes
    ///   nothing.
    /// * After the peer's BYE ends a session whose re-INVITE this user agent
    ///   sent, a late 2xx gets its ACK from the dialog the re-INVITE kept.
    #[test]
    fn bye_during_reinvite_has_single_terminal_usage_result() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let usage = acknowledged(&mut model, &clock);
        let authority = model
            .receive_invite(
                &reinvite_from_caller(314160, "sip:alice@192.0.2.1"),
                offer(),
                clock.now(),
            )
            .unwrap();
        let exchange = authority.exchange;
        let taken = model.receive_request(&from_caller("BYE", 314161), flow());
        model.check();

        assert_eq!(taken, Ok(InDialog::Bye));
        let effects = model.take_effects();
        assert_eq!(statuses(&effects), [487]);
        let ended: Vec<_> = notices(&effects)
            .into_iter()
            .filter(|event| matches!(event, Event::UsageEnded { .. }))
            .collect();
        assert_eq!(
            ended,
            [Event::UsageEnded {
                usage,
                reason: EndReason::RemoteBye { flow: flow() }
            }],
        );
        let late =
            run(&mut model, Command::Accept { authority, answer: answer() });
        assert_eq!(outcome(&model, late), Some(Err(Error::AlreadyFinalized)));
        model.final_committed(exchange, clock.now());
        model.check();
        assert_eq!(model.exchanges.len(), 0);

        // This user agent's BYE crosses its re-INVITE.
        let mut model = self::model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let (operation, exchange, cseq) =
            reinvited(&mut model, usage, Some(answer()), clock.now());
        let terminate = run(&mut model, Command::Terminate { usage });
        assert_eq!(session_byes(&model.take_effects(), usage), 1);
        let bye = model.bye_started(usage, Ok(())).unwrap();
        model.check();
        let effects = model.take_effects();
        assert_eq!(
            notices(&effects),
            [Event::UsageEnded { usage, reason: EndReason::LocalBye }],
        );
        assert_eq!(outcome(&model, operation), Some(Err(Error::SessionEnded)));

        let ok = to_reinvite("200 OK", "callee", "sip:bob@192.0.2.4", cseq);
        model.receive_reinvite_response(
            exchange,
            &ok,
            Some(answer()),
            clock.now(),
        );
        model.check();
        let effects = model.take_effects();
        assert!(notices(&effects).is_empty());
        let ack = acks(&effects)[0];
        let (ack_request, _) = model.ack_request(ack).unwrap();
        assert_eq!(
            protocol::cseq(ack_request.request.headers()).unwrap(),
            (cseq, "ACK")
        );
        model.bye_answered(bye, Ok(()));
        model.reinvite_collection_finished(exchange, clock.now());
        model.check();
        assert!(
            model
                .take_effects()
                .iter()
                .all(|effect| !matches!(effect, Effect::Notify(_)))
        );
        assert_eq!(outcome(&model, terminate), Some(Ok(Completion::Done)));

        // The peer's BYE ends the session while this user agent's re-INVITE
        // waits, and its dialog goes at once.
        let mut model = self::model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let (operation, exchange, cseq) =
            reinvited(&mut model, usage, Some(answer()), clock.now());
        let bye = from_callee("BYE", "callee", 1);
        assert_eq!(model.receive_request(&bye, flow()), Ok(InDialog::Bye));
        model.check();
        assert_eq!(model.dialogs.len(), 0);
        assert_eq!(outcome(&model, operation), Some(Err(Error::SessionEnded)));
        model.take_effects();

        model.receive_reinvite_response(
            exchange,
            &ok_for(cseq),
            Some(answer()),
            clock.now(),
        );
        model.check();
        let ack = acks(&model.take_effects())[0];
        let (ack_request, _) = model.ack_request(ack).unwrap();
        assert_eq!(
            protocol::cseq(ack_request.request.headers()).unwrap(),
            (cseq, "ACK")
        );
    }

    fn ok_for(cseq: u32) -> Response<Bytes> {
        to_reinvite("200 OK", "callee", "sip:bob@192.0.2.4", cseq)
    }

    /// A 481 to a re-INVITE says the peer has no such dialog, and ends the
    /// session without a BYE (RFC 5057 section 5.1). A 408, or no response
    /// at all, ends it with a BYE (RFC 3261 sections 12.2.1.2 and 14.1).
    /// Neither is tried again.
    #[test]
    fn a_failed_reinvite_ends_the_session_when_the_dialog_is_gone() {
        let clock = Clock(Instant::now());
        for (code, bye) in [(Some(481), 0), (Some(408), 1), (None, 1)] {
            let mut model = model(limits());
            let (_, usage, _) = caller_session(&mut model);
            let (operation, exchange, cseq) =
                reinvited(&mut model, usage, Some(answer()), clock.now());
            let error = match code {
                Some(code) => {
                    let failure = to_reinvite(
                        &format!("{code} Failed"),
                        "callee",
                        "sip:bob@192.0.2.4",
                        cseq,
                    );
                    model.receive_reinvite_response(
                        exchange,
                        &failure,
                        None,
                        clock.now(),
                    );
                    Error::RemoteFailure(status(code))
                }
                None => {
                    model.reinvite_transaction_failed(
                        exchange,
                        Error::Timeout,
                        clock.now(),
                    );
                    Error::Timeout
                }
            };
            model.check();
            let effects = model.take_effects();

            assert_eq!(outcome(&model, operation), Some(Err(error)));
            assert_eq!(session_byes(&effects, usage), bye);
            if bye == 1 {
                model.bye_started(usage, Ok(())).unwrap();
            }
            assert_eq!(
                end_of(&model, usage).map(|(reason, _)| reason),
                Some(EndReason::ReinviteFailed(error)),
            );
            assert_eq!(model.next_deadline(), None, "nothing goes again");
        }
    }

    /// A re-INVITE waits while one is open in the dialog either way, while
    /// the 2xx of this user agent waits for its ACK, and while an offer
    /// waits for its answer (RFC 3261 section 14.1, RFC 3264 section 4).
    /// Each is refused with nothing sent.
    #[test]
    fn a_reinvite_waits_for_the_open_exchange() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, _, usage) = accepted(&mut model, &clock);
        let unacknowledged = run(
            &mut model,
            Command::Reinvite { usage, offer: Some(answer()) },
        );
        assert_eq!(
            outcome(&model, unacknowledged),
            Some(Err(Error::InvalidTransition)),
        );
        model.receive_ack(&uas_dialog(), 314159, None);
        model
            .receive_invite(
                &reinvite_from_caller(314160, "sip:alice@192.0.2.1"),
                offer(),
                clock.now(),
            )
            .unwrap();
        model.take_effects();
        let crossing = run(
            &mut model,
            Command::Reinvite { usage, offer: Some(answer()) },
        );
        assert_eq!(
            outcome(&model, crossing),
            Some(Err(Error::InvalidTransition))
        );
        model.check();
        assert!(
            model
                .take_effects()
                .iter()
                .all(|effect| !matches!(effect, Effect::StartReinvite { .. }))
        );

        let mut model = self::model(limits());
        let (_, usage, _) = caller_session(&mut model);
        reinvited(&mut model, usage, Some(answer()), clock.now());
        let second = run(&mut model, Command::Reinvite { usage, offer: None });
        assert_eq!(
            outcome(&model, second),
            Some(Err(Error::InvalidTransition))
        );
        model.check();
    }

    /// A re-INVITE whose responses the core dropped, the final among them,
    /// fails once the core stops collecting them, as an observation that is
    /// not complete, and leaves the session as it was. One the endpoint
    /// never took fails at once, with its offer withdrawn.
    #[test]
    fn a_reinvite_without_its_final_fails_and_changes_nothing() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let before = model.usage_state(usage).unwrap();
        let (operation, exchange, _) =
            reinvited(&mut model, usage, Some(answer()), clock.now());

        model.reinvite_responses_lost(exchange);
        model.reinvite_collection_finished(exchange, clock.now());
        model.check();

        assert_eq!(
            outcome(&model, operation),
            Some(Err(Error::ObservationIncomplete)),
        );
        assert_eq!(model.usage_state(usage).unwrap(), before);
        assert_eq!(model.reinvites, 0);

        let operation = run(
            &mut model,
            Command::Reinvite { usage, offer: Some(answer()) },
        );
        let exchange = started(&model.take_effects());
        model.take_reinvite(exchange).unwrap();
        model.reinvite_started(exchange, Err(Error::Unroutable), clock.now());
        model.check();
        assert_eq!(outcome(&model, operation), Some(Err(Error::Unroutable)));
        assert_eq!(model.usage_state(usage).unwrap(), before);
        assert_eq!(model.reinvites, 0);
    }

    /// A re-INVITE that comes while the offer in this user agent's 2xx
    /// waits for its answer in the ACK gets a 491, as RFC 5407 section
    /// 3.1.5 recommends, since no new offer can start before that answer
    /// (RFC 3264 section 4). Once the ACK brings it, a re-INVITE is taken.
    #[test]
    fn a_reinvite_while_an_offer_waits_gets_a_491() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let authority = model
            .receive_invite(&request(INVITE), Ok(Body::Empty), clock.now())
            .unwrap();
        let exchange = authority.exchange;
        run(&mut model, Command::Accept { authority, answer: answer() });
        model.final_committed(exchange, clock.now());
        model.take_effects();

        let early = model.receive_invite(
            &reinvite_from_caller(314160, "sip:alice@192.0.2.1"),
            offer(),
            clock.now(),
        );
        assert_eq!(early.unwrap_err(), Refusal::RequestPending);
        model.check();

        model.receive_ack(&uas_dialog(), 314159, Some(description("v=0")));
        let later = model.receive_invite(
            &reinvite_from_caller(314160, "sip:alice@192.0.2.1"),
            offer(),
            clock.now(),
        );
        assert!(later.is_ok());
        model.check();
    }

    /// A session takes a re-INVITE while one 2xx of its own waits for its
    /// ACK, and refuses the next with a 491 while two wait, so that a peer
    /// that never acknowledges cannot take every replay context. Once an ACK
    /// comes, the next re-INVITE is taken again.
    #[test]
    fn a_session_keeps_at_most_two_2xx_without_their_ack() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, _, usage) = accepted(&mut model, &clock);

        let second = model
            .receive_invite(
                &reinvite_from_caller(314160, "sip:alice@192.0.2.1"),
                offer(),
                clock.now(),
            )
            .unwrap();
        let exchange = second.exchange;
        run(
            &mut model,
            Command::Accept { authority: second, answer: answer() },
        );
        model.final_committed(exchange, clock.now());
        model.take_effects();
        let third = model.receive_invite(
            &reinvite_from_caller(314161, "sip:alice@192.0.2.1"),
            offer(),
            clock.now(),
        );
        assert_eq!(third.unwrap_err(), Refusal::RequestPending);
        assert_eq!(
            model.usages.get(usage).unwrap().phase(),
            UsagePhase::Established
        );

        model.receive_ack(&uas_dialog(), 314159, None);
        model.take_effects();
        let fourth = model.receive_invite(
            &reinvite_from_caller(314162, "sip:alice@192.0.2.1"),
            offer(),
            clock.now(),
        );
        assert!(fourth.is_ok());
        model.take_effects();
    }

    /// The dialog of [`caller_session`], as the caller sees it.
    fn uac_dialog() -> DialogId {
        DialogId::new(
            "a84b4c76e66710@pc33.atlanta.example.com".into(),
            "1928301774".parse().unwrap(),
            Some("callee".parse().unwrap()),
        )
    }

    /// A response of the caller to a re-INVITE numbered `cseq` that the UAS
    /// of [`accepted`] sent.
    fn to_uas_reinvite(status: &str, cseq: u32) -> Response<Bytes> {
        response(&format!(
            "SIP/2.0 {status}
Via: SIP/2.0/UDP 192.0.2.4;branch=z9hG4bKreinvite
To: <sip:alice@atlanta.example.com>;tag=1928301774
From: <sip:bob@biloxi.example.com>;tag=0000000000000001
Call-ID: a84b4c76e66710@pc33.atlanta.example.com
CSeq: {cseq} INVITE
Contact: <sip:alice@192.0.2.1>

"
        ))
    }

    /// A re-INVITE goes either way, whoever sent the initial INVITE. The
    /// callee's re-INVITE gets its 2xx and ACK, and the caller takes the
    /// callee's re-INVITE and gets its ACK, each a session revision on.
    /// The peer's BYE while the caller's 2xx is on its way ends the session
    /// once, and the 2xx still waits for its ACK.
    #[test]
    fn a_reinvite_goes_either_way() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let usage = acknowledged(&mut model, &clock);
        let operation = run(
            &mut model,
            Command::Reinvite { usage, offer: Some(answer()) },
        );
        let exchange = started(&model.take_effects());
        let (outgoing, _) = model.take_reinvite(exchange).unwrap();
        let (cseq, _) = protocol::cseq(outgoing.request.headers()).unwrap();
        model.reinvite_started(exchange, Ok(()), clock.now());
        model.receive_reinvite_response(
            exchange,
            &to_uas_reinvite("200 OK", cseq),
            Some(answer()),
            clock.now(),
        );
        model.check();
        let ack = acks(&model.take_effects())[0];
        model.ack_written(ack, true);
        model.check();
        assert_eq!(outcome(&model, operation), Some(Ok(Completion::Done)));
        assert_eq!(model.usage_state(usage).unwrap().session_revision, 2);

        let mut model = self::model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let authority = model
            .receive_invite(
                &from_callee("INVITE", "callee", 2),
                offer(),
                clock.now(),
            )
            .unwrap();
        let exchange = authority.exchange;
        assert_eq!(model.reinvite_session(exchange), Some(usage));
        run(&mut model, Command::Accept { authority, answer: answer() });
        model.final_committed(exchange, clock.now());
        model.check();
        model.receive_ack(&uac_dialog(), 2, None);
        model.check();
        assert_eq!(model.usage_state(usage).unwrap().session_revision, 2);

        let authority = model
            .receive_invite(
                &from_callee("INVITE", "callee", 3),
                offer(),
                clock.now(),
            )
            .unwrap();
        let exchange = authority.exchange;
        run(&mut model, Command::Accept { authority, answer: answer() });
        model.take_effects();
        let bye = from_callee("BYE", "callee", 4);
        assert_eq!(model.receive_request(&bye, flow()), Ok(InDialog::Bye));
        model.final_committed(exchange, clock.now());
        model.check();
        let effects = model.take_effects();
        let ended = notices(&effects)
            .into_iter()
            .filter(|event| matches!(event, Event::UsageEnded { .. }))
            .count();
        assert_eq!(ended, 1);
        // The INVITE's own replay context stays until Timer M, beside the
        // one of the 2xx that waits for its ACK.
        assert_eq!(model.replays.len(), 2, "the 2xx waits for its ACK");
        model.receive_ack(&uac_dialog(), 3, None);
        model.check();
        assert_eq!(model.replays.len(), 1);
    }

    /// A late-offer re-INVITE whose response collection ends before the
    /// answer is ready still ends its operation with that answer. One whose
    /// session ended meanwhile fails with `SessionEnded`, and its ACK, which
    /// has to reject the offer, is still built from the dialog.
    #[test]
    fn a_late_offer_reinvite_ends_with_its_answer() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let (operation, exchange, cseq) =
            reinvited(&mut model, usage, None, clock.now());
        model.receive_reinvite_response(
            exchange,
            &ok_for(cseq),
            Some(description("v=0 their offer")),
            clock.now(),
        );
        let replay = match model.take_effects()[..] {
            [Effect::PrepareAnswer { replay, .. }] => replay,
            ref other => panic!("{other:?}"),
        };
        model.reinvite_collection_finished(exchange, clock.now());
        model.check();
        assert_eq!(outcome(&model, operation), None);

        model.answer_prepared(replay, Some(answer()));
        model.check();
        assert_eq!(outcome(&model, operation), Some(Ok(Completion::Done)));

        // This user agent's BYE crosses the 2xx, and the BYE's transaction
        // ends before the answer is in.
        let mut model = self::model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let (operation, exchange, cseq) =
            reinvited(&mut model, usage, None, clock.now());
        run(&mut model, Command::Terminate { usage });
        let bye = model.bye_started(usage, Ok(())).unwrap();
        assert_eq!(outcome(&model, operation), Some(Err(Error::SessionEnded)));
        model.receive_reinvite_response(
            exchange,
            &ok_for(cseq),
            Some(description("v=0 their offer")),
            clock.now(),
        );
        let replay = model
            .take_effects()
            .into_iter()
            .find_map(|effect| match effect {
                Effect::PrepareAnswer { replay, usage: None, .. } => {
                    Some(replay)
                }
                _ => None,
            })
            .unwrap();
        model.bye_answered(bye, Ok(()));
        model.check();
        assert_eq!(model.dialogs.len(), 0);

        model.answer_prepared(replay, Some(description("v=0 rejected")));
        model.check();
        assert_eq!(acks(&model.take_effects()), [replay]);
        let (ack, body) = model.ack_request(replay).unwrap();
        assert_eq!(
            protocol::cseq(ack.request.headers()).unwrap(),
            (cseq, "ACK")
        );
        assert_eq!(body, Some(description("v=0 rejected")));
    }

    /// The callee asks to end a session while the 2xx of the caller's
    /// re-INVITE is on its way to the core. The BYE waits for the ACK of
    /// that 2xx, as for any 2xx of the callee's (RFC 3261 section 15), and
    /// goes once the ACK is in. If the core refuses the 2xx instead, the BYE
    /// goes at once.
    #[test]
    fn a_bye_waits_for_the_ack_of_a_reinvite_2xx_on_its_way() {
        let clock = Clock(Instant::now());
        for refused in [false, true] {
            let mut model = model(limits());
            let usage = acknowledged(&mut model, &clock);
            let authority = model
                .receive_invite(
                    &reinvite_from_caller(314160, "sip:alice@192.0.2.1"),
                    offer(),
                    clock.now(),
                )
                .unwrap();
            let exchange = authority.exchange;
            run(&mut model, Command::Accept { authority, answer: answer() });
            model.take_effects();

            let terminate = run(&mut model, Command::Terminate { usage });
            model.check();
            assert_eq!(session_byes(&model.take_effects(), usage), 0);
            assert_eq!(
                model.usage_state(usage).unwrap().phase,
                UsagePhase::Ending
            );

            if refused {
                model.final_refused(exchange, false);
                model.check();
                let effects = model.take_effects();
                assert_eq!(statuses(&effects), [500]);
                assert_eq!(session_byes(&effects, usage), 1);
            } else {
                model.final_committed(exchange, clock.now());
                model.check();
                assert_eq!(session_byes(&model.take_effects(), usage), 0);
                model.receive_ack(&uas_dialog(), 314160, None);
                model.check();
                assert_eq!(session_byes(&model.take_effects(), usage), 1);
            }
            model.bye_started(usage, Ok(())).unwrap();
            assert_eq!(
                outcome(&model, terminate),
                None,
                "it waits for the 200"
            );
        }
    }

    /// An error response without the dialog's identity is not the peer's,
    /// so a 481 with another Call-ID ends nothing. A 491 while the session
    /// is ending fails the operation at once, with no second try.
    #[test]
    fn a_reinvite_failure_is_taken_only_from_its_peer() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (_, usage, _) = caller_session(&mut model);
        let (operation, exchange, cseq) =
            reinvited(&mut model, usage, Some(answer()), clock.now());
        let stranger = to_reinvite("481 Gone", "callee", "sip:bob@h", cseq);
        let text = String::from_utf8(stranger.to_bytes().to_vec()).unwrap();
        let stranger = response(
            &text.replace("\r\n", "\n").replace("a84b4c76e66710", "elsewhere"),
        );
        model.receive_reinvite_response(
            exchange,
            &stranger,
            None,
            clock.now(),
        );
        model.check();
        assert_eq!(outcome(&model, operation), None);
        assert_eq!(
            model.usage_state(usage).unwrap().phase,
            UsagePhase::Established,
        );

        // An error response from a proxy may carry a To tag of its own.
        let proxy =
            to_reinvite("491 Request Pending", "proxy", "sip:p@h", cseq);
        model.usages.get_mut(usage).unwrap().begin_ending();
        model.usages.get_mut(usage).unwrap().bye = ByeIntent::Deferred {
            operation: None,
            reason: EndReason::LocalBye,
        };
        model.receive_reinvite_response(exchange, &proxy, None, clock.now());
        model.check();
        let glare = Error::RemoteFailure(status(491));
        assert_eq!(outcome(&model, operation), Some(Err(glare)));
        assert_eq!(model.next_deadline(), None, "no second try");
    }

    /// The peer lost its old contact and never got the 2xx of its
    /// re-INVITE, so it sends a newer re-INVITE with its new one, which is
    /// accepted and acknowledged. The older 2xx's ACK deadline then stops
    /// its retransmissions but ends nothing, as RFC 6141 section 5.4
    /// recommends. Without the newer re-INVITE, the deadline ends the
    /// session with a BYE, as RFC 3261 section 14.2 asks. So it does when
    /// the older 2xx carried an offer whose answer the missing ACK owed,
    /// since that exchange can never complete.
    #[test]
    fn a_newer_reinvite_keeps_the_session_past_an_older_ack_deadline() {
        for (newer, offered) in [(true, true), (false, true), (true, false)] {
            let mut clock = Clock(Instant::now());
            let mut model = model(limits());
            let usage = acknowledged(&mut model, &clock);
            let body = if offered { offer() } else { Ok(Body::Empty) };
            let first = model
                .receive_invite(
                    &reinvite_from_caller(314160, "sip:alice@192.0.2.1"),
                    body,
                    clock.now(),
                )
                .unwrap();
            let exchange = first.exchange;
            run(
                &mut model,
                Command::Accept { authority: first, answer: answer() },
            );
            model.final_committed(exchange, clock.now());
            model.take_effects();
            let deadline = clock.now() + T1 * 64;

            if newer {
                clock.advance(T1);
                let recovery = model.receive_invite(
                    &reinvite_from_caller(314161, "sip:alice@192.0.2.77"),
                    offer(),
                    clock.now(),
                );
                // While the older 2xx's offer waits for its answer, the newer
                // re-INVITE is refused, but it was received all the same.
                if let Ok(second) = recovery {
                    let exchange = second.exchange;
                    run(
                        &mut model,
                        Command::Accept {
                            authority: second,
                            answer: answer(),
                        },
                    );
                    model.final_committed(exchange, clock.now());
                    model.receive_ack(&uas_dialog(), 314161, None);
                } else {
                    assert!(!offered);
                }
                model.check();
                model.take_effects();
            }

            let mut effects = Vec::new();
            while let Some(next) =
                model.next_deadline().filter(|at| *at <= deadline)
            {
                effects.extend(advance_to(&mut model, &mut clock, next));
            }

            let kept = newer && offered;
            assert_eq!(
                session_byes(&effects, usage),
                usize::from(!kept),
                "newer {newer}, offered {offered}",
            );
            assert_eq!(
                notices(&effects).contains(&Event::AckTimeout { usage }),
                !kept,
            );
            assert_eq!(model.next_deadline(), None, "no 2xx goes out again");
            if kept {
                let state = model.usage_state(usage).unwrap();
                assert_eq!(state.phase, UsagePhase::Established);
                assert_eq!(state.session_revision, 3);
                assert_eq!(model.replays.len(), 0);
                assert_eq!(model.exchanges.len(), 0);
            }
        }
    }

    /// A BYE the application asked for while the superseded 2xx waited for
    /// its ACK goes at that 2xx's deadline, though the deadline itself ends
    /// nothing.
    #[test]
    fn a_superseded_ack_deadline_still_lets_a_waiting_bye_go() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        let usage = acknowledged(&mut model, &clock);
        let first = model
            .receive_invite(
                &reinvite_from_caller(314160, "sip:alice@192.0.2.1"),
                offer(),
                clock.now(),
            )
            .unwrap();
        let exchange = first.exchange;
        run(
            &mut model,
            Command::Accept { authority: first, answer: answer() },
        );
        model.final_committed(exchange, clock.now());
        let deadline = clock.now() + T1 * 64;
        let newer = model.receive_invite(
            &reinvite_from_caller(314161, "sip:alice@192.0.2.77"),
            offer(),
            clock.now(),
        );
        // The newer re-INVITE is cancelled, which makes it no less received.
        model.receive_cancel(newer.unwrap().exchange);
        let terminate = run(&mut model, Command::Terminate { usage });
        model.take_effects();

        let effects = advance_to(&mut model, &mut clock, deadline);
        model.check();
        assert_eq!(session_byes(&effects, usage), 1);
        assert!(!notices(&effects).contains(&Event::AckTimeout { usage }));
        model.bye_started(usage, Ok(())).unwrap();
        assert_eq!(
            end_of(&model, usage).map(|(reason, _)| reason),
            Some(EndReason::LocalBye),
        );
        assert_eq!(outcome(&model, terminate), None, "it waits for the 200");
    }

    /// A 2xx to this user agent's re-INVITE that comes after the session
    /// ended still moves the target its ACK goes to (RFC 6141 section 4.7),
    /// whether the ACK is built from the Mortal dialog of this user agent's
    /// BYE or from the dialog the re-INVITE kept after the peer's BYE.
    #[test]
    fn a_late_2xx_is_acknowledged_at_its_new_contact() {
        let clock = Clock(Instant::now());
        for ours in [true, false] {
            let mut model = model(limits());
            let (_, usage, _) = caller_session(&mut model);
            let (_, exchange, cseq) =
                reinvited(&mut model, usage, Some(answer()), clock.now());
            if ours {
                run(&mut model, Command::Terminate { usage });
                model.bye_started(usage, Ok(())).unwrap();
            } else {
                let bye = from_callee("BYE", "callee", 1);
                assert_eq!(
                    model.receive_request(&bye, flow()),
                    Ok(InDialog::Bye)
                );
            }
            model.take_effects();

            let moved =
                to_reinvite("200 OK", "callee", "sip:bob@192.0.2.99", cseq);
            model.receive_reinvite_response(
                exchange,
                &moved,
                Some(answer()),
                clock.now(),
            );
            model.check();
            let ack = acks(&model.take_effects())[0];
            let (outgoing, _) = model.ack_request(ack).unwrap();

            assert_eq!(
                outgoing.request.uri().as_str(),
                "sip:bob@192.0.2.99",
                "ours {ours}"
            );
            assert_eq!(&*outgoing.target.next_hop, "sip:bob@192.0.2.99");
            assert_eq!(
                protocol::cseq(outgoing.request.headers()).unwrap(),
                (cseq, "ACK"),
            );
        }
    }

    /// Each table refuses what does not fit, with the outcome its limit
    /// defines and nothing on the wire that the limit does not call for:
    ///
    /// * An INVITE beyond the attempts fails with `CapacityExceeded`, and
    ///   nothing is sent.
    /// * A route set longer than the limit forms no dialog. An INVITE with
    ///   one is refused with a 500, and a 2xx with one gets no ACK and leaves
    ///   its attempt incomplete.
    /// * A re-INVITE beyond the limit of re-INVITEs gets a 503, and the
    ///   application's own fails with `CapacityExceeded`, with nothing sent.
    #[test]
    fn each_table_refuses_at_its_limit() {
        let clock = Clock(Instant::now());

        let mut model = model(Limits { attempts: 1, ..limits() });
        let first = run(&mut model, Command::Invite { plan: plan() });
        let second = run(&mut model, Command::Invite { plan: plan() });
        let effects = model.take_effects();
        assert_eq!(
            effects
                .iter()
                .filter(|effect| matches!(effect, Effect::StartInvite { .. }))
                .count(),
            1,
        );
        assert_eq!(
            outcome(&model, second),
            Some(Err(Error::CapacityExceeded))
        );
        assert_eq!(outcome(&model, first), None);

        let mut model = self::model(Limits { routes: 2, ..limits() });
        let refused =
            model.receive_invite(&request(INVITE), offer(), clock.now());
        assert_eq!(refused.unwrap_err().status().as_u16(), 500);
        let attempt = model.start_attempt(&request(INVITE), true).unwrap();
        let routed = reply(
            "200 OK",
            "callee",
            "sip:bob@192.0.2.4",
            "Record-Route: <sip:a.example.com;lr>, <sip:b.example.com;lr>, \
             <sip:c.example.com;lr>\n",
        );
        let taken = model.receive_2xx(attempt, &routed, Some(answer()));
        assert_eq!(taken, Err(Error::InvalidInput));
        assert_eq!(acks(&model.take_effects()), []);
        assert_eq!(
            progress(&model, attempt),
            Some((Some(AttemptResult::Answered), false))
        );

        let mut model = self::model(Limits { reinvites: 1, ..limits() });
        let (_, caller, _) = caller_session(&mut model);
        let callee = acknowledged(&mut model, &clock);
        reinvited(&mut model, caller, Some(answer()), clock.now());
        let peer = model.receive_invite(
            &reinvite_from_caller(314160, "sip:alice@192.0.2.1"),
            offer(),
            clock.now(),
        );
        assert_eq!(peer.unwrap_err(), Refusal::Busy);
        let own = run(
            &mut model,
            Command::Reinvite { usage: callee, offer: Some(answer()) },
        );
        assert_eq!(
            model.take_effects(),
            [Effect::OperationEnded { operation: own }]
        );
        assert_eq!(outcome(&model, own), Some(Err(Error::CapacityExceeded)));
    }

    /// A set of responses the core could not deliver whole is never
    /// reported as complete, whatever came of it. An attempt whose 2xx came
    /// is answered and incomplete. A re-INVITE whose final may be among
    /// those lost fails with `ObservationIncomplete`, and leaves the session
    /// as it was, rather than succeed or count as the endpoint stopping.
    #[test]
    fn responses_overflow_is_not_reported_as_complete_success() {
        let clock = Clock(Instant::now());
        let mut model = model(limits());
        let (attempt, usage, _) = caller_session(&mut model);
        model.responses_lost(attempt);
        model.response_collection_finished(attempt);
        assert_eq!(
            ended(&model.take_effects()),
            (AttemptResult::Answered, false),
        );

        let (operation, exchange, _) =
            reinvited(&mut model, usage, Some(answer()), clock.now());
        model.reinvite_responses_lost(exchange);
        model.reinvite_collection_finished(exchange, clock.now());
        model.take_effects();
        assert_eq!(
            outcome(&model, operation),
            Some(Err(Error::ObservationIncomplete)),
        );
        let state = model.usage_state(usage).unwrap();
        assert_eq!(
            (state.phase, state.negotiation, state.session_revision),
            (UsagePhase::Established, Negotiation::Stable, 1),
        );
    }

    /// With a slot in each table, every record reuses the slot the one
    /// before it had. Inputs that name the earlier records, as late results
    /// of jobs or timers do, find nothing. The record in the slot now stays
    /// as it is, and nothing is sent.
    #[test]
    fn generation_reuse_under_load_is_safe() {
        let clock = Clock(Instant::now());
        let mut model = model(Limits {
            incoming: 1,
            dialogs: 1,
            usages: 1,
            replays: 1,
            reinvites: 1,
            ..limits()
        });
        let mut exchanges = Vec::new();
        let mut replays = Vec::new();
        for n in 0..200 {
            let call = format!("reuse{n}@example.com");
            let authority =
                model.receive_invite(&invite(&call), offer(), clock.now());
            let exchange = authority.as_ref().unwrap().exchange;
            run(
                &mut model,
                Command::Accept {
                    authority: authority.unwrap(),
                    answer: answer(),
                },
            );
            model.final_committed(exchange, clock.now());
            let effects = model.take_effects();
            let (_, usage) = confirmed(&effects);
            let replay = model
                .replays
                .iter()
                .find(|(_, replay)| replay.usage == Some(usage))
                .map(|(key, _)| key)
                .unwrap();
            let id = model.replays.get(replay).unwrap().id.dialog.clone();
            model.receive_ack(&id, 314159, None);
            model.end_usage(usage, EndReason::LocalBye);
            model.take_effects();
            for effect in effects {
                if let Effect::OperationEnded { operation } = effect {
                    model.take_outcome(operation);
                }
            }
            exchanges.push(exchange);
            replays.push(replay);
        }
        let authority = model
            .receive_invite(&invite("live@example.com"), offer(), clock.now())
            .unwrap();
        let live = authority.exchange;
        assert!(!exchanges.contains(&live), "the generation moved on");
        model.take_effects();

        for (&exchange, &replay) in exchanges.iter().zip(&replays) {
            model.final_committed(exchange, clock.now());
            model.final_refused(exchange, false);
            model.receive_cancel(exchange);
            model.abandon(exchange);
            model.provisional_done(
                exchange,
                status(180),
                None,
                None,
                Ok(()),
                clock.now(),
            );
            model.answer_prepared(replay, Some(answer()));
            model.ack_written(replay, true);
            model.bye_done(replay);
        }

        assert_eq!(model.take_effects(), []);
        let record = model.exchanges.get(live).unwrap();
        assert_eq!(record.state(), ExchangeState::Pending);
        assert_eq!(authority.exchange, live);
    }

    /// Every timer is set again only within its bound. The copies of a 2xx
    /// stop at its ACK deadline, 64 T1 after it went, and the provisional
    /// sent again every minute stops at the decision deadline. Once both
    /// passed, no timer is left. A re-INVITE that gets a 491 goes once more,
    /// and not a third time (see `glare_retry_allocates_new_cseq_and_transaction`).
    #[test]
    fn retries_and_timer_entries_remain_bounded() {
        let mut clock = Clock(Instant::now());
        let mut model = model(limits());
        accepted(&mut model, &clock);
        let ringing = model
            .receive_invite(
                &invite("ringing@example.com"),
                offer(),
                clock.now(),
            )
            .unwrap();
        let exchange = ringing.exchange;
        let operation = run(
            &mut model,
            Command::Provisional {
                exchange,
                status: status(180),
                preview: None,
            },
        );
        model.take_effects();
        model.provisional_done(
            exchange,
            status(180),
            None,
            Some(operation),
            Ok(()),
            clock.now(),
        );
        model.take_effects();

        let (mut copies, mut provisionals) = (0, 0);
        while let Some(due) = model.next_deadline() {
            for effect in advance_to(&mut model, &mut clock, due) {
                match effect {
                    Effect::Resend2xx { .. } => copies += 1,
                    Effect::SubmitProvisional { .. } => provisionals += 1,
                    Effect::SubmitFinal { exchange, .. } => {
                        model.final_committed(exchange, clock.now());
                    }
                    Effect::SendSessionBye { usage } => {
                        model.bye_started(usage, Err(Error::TransportFailure));
                    }
                    _ => {}
                }
            }
            model.take_effects();
        }

        // 2xx copies at 0.5, 1.5, 3.5, 7.5 and every 4 s until 32 s.
        assert_eq!(copies, 10);
        // A provisional every minute until the 500 at three minutes.
        assert_eq!(provisionals, 2);
        assert_eq!(model.timers.len(), 0);
        assert_eq!(ringing.exchange, exchange);
    }

    /// A header value that is malformed, extreme or repeated, a route set
    /// longer than the limit, or an extension the UA does not know is
    /// refused or taken, never a panic. What the UA takes stays within its
    /// tables, which the checks after every input confirm, and is gone once
    /// everything settled.
    #[test]
    fn malformed_message_cannot_create_unbounded_state() {
        fn property(mutations: Vec<(u8, u8, u8)>) -> bool {
            let mut simulation = Simulation::new(limits());
            for (n, &(kind, line, value)) in mutations.iter().enumerate() {
                let text = mutate(n, kind, line, value);
                let Ok(message) = Request::from_bytes(text.as_bytes()) else {
                    continue;
                };
                simulation.receive(&message, value);
                simulation.settle();
            }
            simulation.quiesce();
            let model = &simulation.model;
            assert_eq!(model.exchanges.len(), 0);
            assert_eq!(model.replays.len(), 0);
            assert!(model.dialogs.len() <= model.limits.dialogs);
            true
        }

        quickcheck::QuickCheck::new()
            .rng(quickcheck::Gen::new(100))
            .quickcheck(property as fn(Vec<(u8, u8, u8)>) -> bool);
    }

    /// Values a peer could put in a header, from the plausible to the
    /// hostile.
    const VALUES: [&str; 16] = [
        "",
        ";;;",
        "<sip:",
        "4294967295 INVITE",
        "2147483648 INVITE",
        "-1 INVITE",
        "1 BYE",
        "<sip:a@192.0.2.9>;tag=",
        "<sip:a@192.0.2.9>;tag=x, <sip:b@192.0.2.9>",
        "\"unterminated <sip:a@192.0.2.9>",
        "<sips:a@192.0.2.9;lr>",
        "<sip:a@[2001:db8::1]:5060;lr;maddr=192.0.2.1>",
        "100rel, x-unknown",
        "4294967295",
        "application/sdp; charset=\"",
        "<sip:a@192.0.2.9;method=BYE?Route=x>",
    ];

    /// Makes the `n`th message of a script: the INVITE of the fixtures, as
    /// a new INVITE, a request in a dialog or an ACK by `kind`, with one of
    /// its lines dropped, repeated or given one of [`VALUES`] by `line` and
    /// `value`.
    fn mutate(n: usize, kind: u8, line: u8, value: u8) -> String {
        let call = format!("call{}@example.com", n % 5);
        let text =
            INVITE.replace("a84b4c76e66710@pc33.atlanta.example.com", &call);
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        lines.retain(|line| !line.is_empty());
        match kind % 4 {
            0 => {}
            1 => {
                lines[0] = lines[0].replace("INVITE", "BYE");
                lines[2] = "To: Bob <sip:bob@biloxi.example.com>;tag=0000000000000001".into();
            }
            2 => {
                lines[0] = lines[0].replace("INVITE", "ACK");
                lines[2] = "To: Bob <sip:bob@biloxi.example.com>;tag=0000000000000001".into();
            }
            _ => lines.push("Expires: 4294967295".into()),
        }
        let index = 1 + usize::from(line) % (lines.len() - 1);
        let name = lines[index].split(':').next().unwrap().to_owned();
        let header = |value: &str| format!("{name}: {value}");
        match value % 4 {
            // A Via the core would not have, or a CSeq or Call-ID of another
            // shape, still parses, so these only drop or change values.
            0 if name != "Via" => drop(lines.remove(index)),
            1 => {
                let repeated = lines[index].clone();
                let times = usize::from(line % 40);
                lines.extend(std::iter::repeat_n(repeated, times));
            }
            _ => {
                let value = VALUES[usize::from(value / 4) % VALUES.len()];
                lines[index] = header(value);
            }
        }
        let mut text = lines.join("\n");
        text.push_str("\n\n");
        text.replace('\n', "\r\n")
    }

    /// What the runtime owes the model once a job or a watcher ends.
    #[derive(Debug)]
    enum Owed {
        Final(ExchangeKey),
        Provisional {
            exchange: ExchangeKey,
            status: StatusCode,
            preview: Option<Description>,
            operation: Option<OperationId>,
        },
        Invite(AttemptKey),
        Reinvite(ExchangeKey),
        Ack(ReplayKey),
        Bye(ReplayKey),
        SessionBye(UsageKey),
        ByeResponse(ByeStarted),
        Cancel(Option<OperationId>),
        Answer(ReplayKey),
    }

    /// The model with a runtime of the test's own. It does with each effect
    /// what the driver does at once, such as build an ACK, and leaves what
    /// waits on the core, the network or a negotiator for a script to settle,
    /// in whatever order the script picks. A script also plays the
    /// application and the peers, from what the tables hold.
    struct Simulation {
        model: Model<Counter>,
        now: Instant,
        owed: Vec<Owed>,
        authorities: Vec<Authority>,
        /// The re-INVITEs the core took, which the peer may answer.
        reinvites: Vec<ExchangeKey>,
        calls: u32,
        /// The next CSeq number of a request from a peer, above any number the
        /// UA picks or the fixtures use, so each is new in its dialog.
        cseq: u32,
    }

    /// A request a peer sends in the dialog `id` names, as this user agent
    /// knows the dialog.
    fn peer_request(id: &DialogId, method: &str, cseq: u32) -> Request<Bytes> {
        let from =
            id.remote_tag().map_or(String::new(), |tag| format!(";tag={tag}"));
        request(&format!(
            "{method} sip:ua@192.0.2.1 SIP/2.0
Via: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bK-{method}-{cseq}
Max-Forwards: 70
To: <sip:ua@192.0.2.1>;tag={local}
From: <sip:peer@192.0.2.9>{from}
Call-ID: {call}
CSeq: {cseq} {method}
Contact: <sip:peer@192.0.2.{host}>

",
            local = id.local_tag(),
            call = id.call_id(),
            host = 10 + cseq % 200,
        ))
    }

    /// A response of the peer to an INVITE numbered `cseq` that this user
    /// agent sent in the dialog `id` names.
    fn peer_response(
        id: &DialogId,
        status: &str,
        cseq: u32,
    ) -> Response<Bytes> {
        let (to, host) = match id.remote_tag() {
            Some(tag) => (format!(";tag={tag}"), tag.as_str()),
            None => (String::new(), "none"),
        };
        response(&format!(
            "SIP/2.0 {status}
Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-sim
To: <sip:peer@192.0.2.9>{to}
From: <sip:ua@192.0.2.1>;tag={local}
Call-ID: {call}
CSeq: {cseq} INVITE
Contact: <sip:{host}@192.0.2.9>

",
            local = id.local_tag(),
            call = id.call_id(),
        ))
    }

    /// Picks the `index`th of `items`, wrapping around, or `None` from none.
    fn pick<T: Clone>(items: &[T], index: u8) -> Option<T> {
        (!items.is_empty())
            .then(|| items[usize::from(index) % items.len()].clone())
    }

    impl Simulation {
        fn new(limits: Limits) -> Simulation {
            Simulation {
                model: model(limits),
                now: Instant::now(),
                owed: Vec::new(),
                authorities: Vec::new(),
                reinvites: Vec::new(),
                calls: 0,
                cseq: 400_000,
            }
        }

        /// Carries out the effects until there are none, as the driver's
        /// `settle` does. Taking them checks the tables each time.
        fn settle(&mut self) {
            loop {
                let effects = self.model.take_effects();
                if effects.is_empty() {
                    return;
                }
                for effect in effects {
                    self.apply(effect);
                }
            }
        }

        fn apply(&mut self, effect: Effect) {
            let owed = match effect {
                Effect::SubmitFinal { exchange, .. } => Owed::Final(exchange),
                Effect::SubmitProvisional {
                    exchange,
                    status,
                    preview,
                    operation,
                    ..
                } => {
                    Owed::Provisional { exchange, status, preview, operation }
                }
                Effect::StartInvite { attempt } => {
                    if self.model.take_invite(attempt).is_none() {
                        return;
                    }
                    Owed::Invite(attempt)
                }
                Effect::StartReinvite { exchange } => {
                    if self.model.take_reinvite(exchange).is_none() {
                        return;
                    }
                    Owed::Reinvite(exchange)
                }
                Effect::PrepareAnswer { replay, .. } => Owed::Answer(replay),
                Effect::SendAck { replay } => {
                    if self.model.ack_request(replay).is_none() {
                        self.model.ack_written(replay, false);
                        return;
                    }
                    Owed::Ack(replay)
                }
                Effect::SendBye { replay } => {
                    if self.model.bye_request(replay).is_none() {
                        self.model.bye_done(replay);
                        return;
                    }
                    Owed::Bye(replay)
                }
                Effect::SendSessionBye { usage } => {
                    if let Err(error) = self.model.session_bye_request(usage) {
                        self.model.bye_started(usage, Err(error));
                        return;
                    }
                    Owed::SessionBye(usage)
                }
                Effect::CancelInvite { operation, .. } => {
                    Owed::Cancel(operation)
                }
                Effect::OperationEnded { operation } => {
                    self.model.take_outcome(operation);
                    return;
                }
                Effect::Resend2xx { .. }
                | Effect::ResendAck { .. }
                | Effect::AttemptEnded { .. }
                | Effect::Notify(_)
                | Effect::Released(_) => return,
            };
            self.owed.push(owed);
        }

        /// Takes in a request a peer sent, as the driver does by its method,
        /// with the body of an offer or none by `choice`.
        fn receive(&mut self, request: &Request<Bytes>, choice: u8) {
            let now = self.now;
            let method = request.method().clone();
            if method == Method::ACK {
                let answer = (choice % 2 == 0).then(answer);
                self.model.receive_ack_request(request, answer);
            } else if method == Method::INVITE {
                let body =
                    if choice % 2 == 0 { offer() } else { Ok(Body::Empty) };
                if let Ok(authority) =
                    self.model.receive_invite(request, body, now)
                {
                    self.authorities.push(authority);
                }
            } else {
                let _ = self.model.classify(request);
                let _ = self.model.knows_dialog(request);
                let _ = self.model.receive_request(request, flow());
            }
        }

        /// Settles one thing the runtime owes, well or badly.        /// Settles one thing the runtime owes, well or badly.
        fn resolve(&mut self, index: usize, well: bool, choice: u8) {
            if self.owed.is_empty() {
                return;
            }
            let owed = self.owed.swap_remove(index % self.owed.len());
            let now = self.now;
            let model = &mut self.model;
            match owed {
                Owed::Final(exchange) if well => {
                    model.final_committed(exchange, now);
                }
                Owed::Final(exchange) => {
                    model.final_refused(exchange, choice % 2 == 0);
                }
                Owed::Provisional { exchange, status, preview, operation } => {
                    let result = if well {
                        Ok(())
                    } else {
                        Err(Error::AlreadyFinalized)
                    };
                    model.provisional_done(
                        exchange, status, preview, operation, result, now,
                    );
                }
                Owed::Invite(attempt) if well => model.invite_started(attempt),
                Owed::Invite(attempt) => {
                    model.invite_failed(attempt, Error::Unroutable);
                }
                Owed::Reinvite(exchange) if well => {
                    model.reinvite_started(exchange, Ok(()), now);
                    self.reinvites.push(exchange);
                }
                Owed::Reinvite(exchange) => {
                    let error = Error::CoreSubmissionRejected;
                    model.reinvite_started(exchange, Err(error), now);
                }
                Owed::Ack(replay) => model.ack_written(replay, well),
                Owed::Bye(replay) => model.bye_done(replay),
                Owed::SessionBye(usage) => {
                    let result = if well {
                        Ok(())
                    } else {
                        Err(Error::TransportFailure)
                    };
                    if let Some(bye) = model.bye_started(usage, result) {
                        self.owed.push(Owed::ByeResponse(bye));
                    }
                }
                Owed::ByeResponse(bye) => {
                    let result = match choice % 3 {
                        _ if well => Ok(()),
                        0 => Err(Error::RemoteFailure(status(481))),
                        _ => Err(Error::Timeout),
                    };
                    model.bye_answered(bye, result);
                }
                Owed::Cancel(operation) => {
                    let result = if well {
                        Ok(CancelResult::Sent)
                    } else {
                        Err(Error::TransportFailure)
                    };
                    model.cancel_done(operation, result);
                }
                Owed::Answer(replay) => {
                    model.answer_prepared(replay, well.then(answer));
                }
            }
        }

        /// Submits a command as the application, and runs it. A command the
        /// UA refuses comes back, with the authority it carried.
        fn command(&mut self, command: Command) {
            match self.model.try_submit(command) {
                Ok(_) => self.model.run_commands(),
                Err(refused) => {
                    if let Command::Accept { authority, .. }
                    | Command::Reject { authority, .. } = refused.command
                    {
                        self.authorities.push(authority);
                    }
                }
            }
        }

        fn next_cseq(&mut self) -> u32 {
            self.cseq += 1;
            self.cseq
        }

        /// The dialogs a peer can send requests in: those in the table, and
        /// the early dialogs of INVITEs this user agent has not answered.
        fn dialogs(&self) -> Vec<DialogId> {
            let mut dialogs: Vec<DialogId> = self
                .model
                .dialogs
                .iter()
                .map(|(_, dialog)| dialog.id().clone())
                .collect();
            for (_, exchange) in self.model.exchanges.iter() {
                if let Scope::Incoming {
                    kind: Received::Initial { dialog: Some(dialog), .. },
                    ..
                } = &exchange.scope
                {
                    dialogs.push(dialog.id().clone());
                }
            }
            dialogs
        }

        /// Takes one step of a script, with `kind` choosing what happens and
        /// `a` and `b` choosing among what the tables hold.
        fn step(&mut self, kind: u8, a: u8, b: u8) {
            let now = self.now;
            match kind % 16 {
                // A new INVITE, with an offer or without.
                0 => {
                    self.calls += 1;
                    let call = format!("call{}@example.com", self.calls);
                    let body =
                        if a % 2 == 0 { offer() } else { Ok(Body::Empty) };
                    if let Ok(authority) =
                        self.model.receive_invite(&invite(&call), body, now)
                    {
                        self.authorities.push(authority);
                    }
                }
                // The application decides an INVITE, or drops it.
                1 | 2 => {
                    if self.authorities.is_empty() {
                        return;
                    }
                    let index = usize::from(a) % self.authorities.len();
                    let authority = self.authorities.swap_remove(index);
                    let exchange = authority.exchange;
                    match b % 5 {
                        0 | 1 => self.command(Command::Accept {
                            authority,
                            answer: answer(),
                        }),
                        2 => self.command(Command::Reject {
                            authority,
                            status: status(486),
                        }),
                        3 => {
                            self.authorities.push(authority);
                            self.command(Command::Provisional {
                                exchange,
                                status: status(180),
                                preview: (a % 2 == 0).then(answer),
                            });
                        }
                        _ => self.model.abandon(authority.exchange),
                    }
                }
                // The caller cancels an INVITE this user agent holds.
                3 => {
                    let incoming: Vec<ExchangeKey> = self
                        .model
                        .exchanges
                        .iter()
                        .filter(|(_, exchange)| {
                            matches!(exchange.scope, Scope::Incoming { .. })
                        })
                        .map(|(key, _)| key)
                        .collect();
                    if let Some(exchange) = pick(&incoming, a) {
                        self.model.receive_cancel(exchange);
                    }
                }
                // The peer acknowledges a 2xx this user agent sent or is
                // sending, with an answer or without.
                4 => {
                    let mut acks: Vec<(DialogId, u32)> = self
                        .model
                        .replays
                        .iter()
                        .filter(|(_, replay)| {
                            replay.id.direction == Direction::Incoming
                        })
                        .map(|(_, replay)| {
                            (replay.id.dialog.clone(), replay.id.cseq)
                        })
                        .collect();
                    for (_, exchange) in self.model.exchanges.iter() {
                        let id = match &exchange.scope {
                            Scope::Incoming {
                                kind:
                                    Received::Initial {
                                        dialog: Some(dialog), ..
                                    },
                                ..
                            } => dialog.id().clone(),
                            Scope::Incoming {
                                kind: Received::Reinvite { dialog, .. },
                                ..
                            } => dialog.clone(),
                            _ => continue,
                        };
                        acks.push((id, exchange.cseq));
                    }
                    if let Some((id, cseq)) = pick(&acks, a) {
                        let answer = (b % 2 == 0).then(answer);
                        self.model.receive_ack(&id, cseq, answer);
                    }
                }
                // The peer sends a BYE, an OPTIONS or a re-INVITE in a
                // dialog.
                5 | 6 => {
                    let Some(id) = pick(&self.dialogs(), a) else {
                        return;
                    };
                    let cseq = if b % 7 == 0 { 1 } else { self.next_cseq() };
                    match b % 3 {
                        0 => {
                            let bye = peer_request(&id, "BYE", cseq);
                            let _ = self.model.receive_request(&bye, flow());
                        }
                        1 => {
                            let options = peer_request(&id, "OPTIONS", cseq);
                            let _ =
                                self.model.receive_request(&options, flow());
                        }
                        _ => {
                            let reinvite = peer_request(&id, "INVITE", cseq);
                            let body = if a % 2 == 0 {
                                offer()
                            } else {
                                Ok(Body::Empty)
                            };
                            if let Ok(authority) =
                                self.model.receive_invite(&reinvite, body, now)
                            {
                                self.authorities.push(authority);
                            }
                        }
                    }
                }
                // The application sends an INVITE, with an offer or without.
                7 => {
                    let mut plan = plan();
                    if a % 3 == 0 {
                        let uri = |text: &str| text.parse().unwrap();
                        *plan = InvitePlan::without_offer(
                            uri("sip:bob@biloxi.example.com"),
                            uri("sip:alice@atlanta.example.com"),
                        );
                    }
                    self.command(Command::Invite { plan });
                }
                // A peer answers an INVITE the core took for this user agent.
                8 | 9 => {
                    let started: Vec<AttemptKey> = self
                        .model
                        .attempts
                        .iter()
                        .filter(|(_, attempt)| attempt.started())
                        .map(|(key, _)| key)
                        .collect();
                    let Some(attempt) = pick(&started, a) else {
                        return;
                    };
                    let record = self.model.attempts.get(attempt).unwrap();
                    let tag: Tag = ["a", "b", "c"][usize::from(b / 8) % 3]
                        .parse()
                        .unwrap();
                    let id = record.origin.dialog_id(Some(tag));
                    let cseq = record.origin.cseq();
                    let description = (b % 4 != 0).then(answer);
                    let _ = match b % 8 {
                        0 | 1 => self.model.receive_provisional(
                            attempt,
                            &peer_response(&id, "180 Ringing", cseq),
                            description,
                        ),
                        2..=4 => self.model.receive_2xx(
                            attempt,
                            &peer_response(&id, "200 OK", cseq),
                            description,
                        ),
                        5 => {
                            let error = Error::RemoteFailure(status(486));
                            self.model.attempt_failed(attempt, error);
                            Ok(())
                        }
                        6 => {
                            self.model.responses_lost(attempt);
                            Ok(())
                        }
                        _ => {
                            self.model.response_collection_finished(attempt);
                            Ok(())
                        }
                    };
                }
                // The application cancels or gives up an INVITE it sent.
                10 => {
                    let attempts: Vec<AttemptKey> = self
                        .model
                        .attempts
                        .iter()
                        .map(|(key, _)| key)
                        .collect();
                    if let Some(attempt) = pick(&attempts, a) {
                        self.command(if b % 2 == 0 {
                            Command::Cancel { attempt }
                        } else {
                            Command::Abandon { attempt }
                        });
                    }
                }
                // The application ends a session or sends a re-INVITE.
                11 => {
                    let usages: Vec<UsageKey> =
                        self.model.usages.iter().map(|(key, _)| key).collect();
                    if let Some(usage) = pick(&usages, a) {
                        self.command(match b % 3 {
                            0 => Command::Terminate { usage },
                            1 => Command::Reinvite {
                                usage,
                                offer: Some(answer()),
                            },
                            _ => Command::Reinvite { usage, offer: None },
                        });
                    }
                }
                // The peer answers a re-INVITE this user agent sent.
                12 => {
                    self.reinvites.retain(|&exchange| {
                        self.model.exchanges.get(exchange).is_some()
                    });
                    let Some(exchange) = pick(&self.reinvites, a) else {
                        return;
                    };
                    let record = self.model.exchanges.get(exchange).unwrap();
                    let Scope::Reinvite(sent) = &record.scope else {
                        return;
                    };
                    let (id, cseq) = (sent.dialog.clone(), record.cseq);
                    let description = (b % 4 != 0).then(answer);
                    let code = [
                        "200 OK",
                        "180 Ringing",
                        "491 Request Pending",
                        "481 Call Does Not Exist",
                        "408 Request Timeout",
                        "488 Not Acceptable Here",
                    ];
                    match b % 9 {
                        0..=5 => {
                            let response = peer_response(
                                &id,
                                code[usize::from(b % 9)],
                                cseq,
                            );
                            self.model.receive_reinvite_response(
                                exchange,
                                &response,
                                description,
                                now,
                            );
                        }
                        6 => self.model.reinvite_transaction_failed(
                            exchange,
                            Error::Timeout,
                            now,
                        ),
                        7 => self.model.reinvite_responses_lost(exchange),
                        _ => self
                            .model
                            .reinvite_collection_finished(exchange, now),
                    }
                }
                // Something the runtime owes is settled.
                13 | 14 => {
                    self.resolve(usize::from(a), b % 4 != 0, b);
                }
                // Time passes.
                _ => {
                    let seconds = [0.05, 0.5, 2.0, 5.0, 33.0, 200.0];
                    let by = seconds[usize::from(a) % seconds.len()];
                    self.now += Duration::from_secs_f64(by);
                    self.model.fire_timers(self.now);
                }
            }
        }

        /// Settles everything, as a runtime that keeps running and peers that
        /// stop sending would, until nothing changes.
        fn quiesce(&mut self) {
            for _ in 0..32 {
                for authority in std::mem::take(&mut self.authorities) {
                    self.model.abandon(authority.exchange);
                }
                self.settle();
                while !self.owed.is_empty() {
                    self.resolve(0, true, 1);
                    self.settle();
                }
                let attempts: Vec<AttemptKey> =
                    self.model.attempts.iter().map(|(key, _)| key).collect();
                for attempt in attempts {
                    self.model.response_collection_finished(attempt);
                }
                for exchange in std::mem::take(&mut self.reinvites) {
                    self.model
                        .reinvite_collection_finished(exchange, self.now);
                }
                self.settle();
                if self.owed.is_empty() && self.model.timers.next().is_none() {
                    return;
                }
                self.now += Duration::from_secs(300);
                self.model.fire_timers(self.now);
                self.settle();
            }
            panic!("the model never settled: {:?}", self.owed);
        }
    }

    /// Runs a script of steps on a model with small tables, so that every
    /// limit is met and slots are reused, then lets everything settle. The
    /// tables are checked after every input. Once settled, no operation is
    /// left without an outcome, no timer is set, and nothing is kept but the
    /// sessions that are still up.
    fn run_script(preset: u8, script: Vec<(u8, u8, u8)>) -> bool {
        let limits = match preset % 3 {
            0 => Limits {
                attempts: 1,
                incoming: 1,
                dialogs: 2,
                usages: 2,
                replays: 2,
                forks: 1,
                cleanups: 1,
                operations: 3,
                commands: 2,
                reinvites: 1,
                ..limits()
            },
            1 => limits(),
            _ => Limits {
                attempts: 8,
                incoming: 8,
                dialogs: 16,
                usages: 16,
                replays: 32,
                forks: 4,
                cleanups: 4,
                operations: 64,
                commands: 8,
                reinvites: 16,
                ..limits()
            },
        };
        let mut simulation = Simulation::new(limits);

        for (kind, a, b) in script {
            simulation.step(kind, a, b);
            simulation.settle();
        }
        simulation.quiesce();

        let model = &simulation.model;
        assert_eq!(model.operations.running().count(), 0, "a stuck operation");
        assert_eq!(model.timers.len(), 0);
        assert_eq!(model.attempts.len(), 0);
        assert_eq!(model.exchanges.len(), 0);
        assert_eq!(model.replays.len(), 0);
        assert_eq!(model.dialogs.len(), model.usages.len(), "a Mortal dialog");
        assert!(model.byes.is_empty());
        true
    }

    /// `QUICKCHECK_TESTS` sets how many scripts run, for a longer search
    /// than the 400 of a test run.
    #[test]
    fn any_order_of_inputs_keeps_the_tables_consistent() {
        let mut checker =
            quickcheck::QuickCheck::new().rng(quickcheck::Gen::new(200));
        if std::env::var_os("QUICKCHECK_TESTS").is_none() {
            checker = checker.tests(400);
        }
        checker.quickcheck(run_script as fn(u8, Vec<(u8, u8, u8)>) -> bool);
    }
}
