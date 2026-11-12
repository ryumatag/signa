/*!
The UA's public handles, events and configuration. The driver that runs them
is in `driver`.
*/

use std::{
    error, fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use signa_core::{
    Request, StatusCode,
    endpoint::{Endpoint, Incoming, Reception, Target},
    transaction::Timers,
    transport::Flow,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    time::Instant,
};

pub use crate::{
    error::{Error, WireEffect},
    invite::{AttemptResult, CancelResult, EndReason},
    negotiation::Description,
    plan::{InvitePlan, ReinvitePlan},
    routing::{ResolveError, StaticResolver},
};
use crate::{
    invite::{AttemptKey, ExchangeKey, UsageKey, UsagePhase},
    model::{self, Authority, Limits, UsageState},
    negotiation::Negotiation,
    operation::Completion,
    routing::{Place, allowed_in},
    timer,
};

mod driver;

/// Resolves the next hop of a request to a transport and socket address.
///
/// The UA calls it for each request it sends outside a transaction's reply
/// path: an INVITE or re-INVITE, the ACK of each 2xx, and each BYE. Each
/// call runs as a task of its own, so a slow resolution holds up only its own
/// request. The UA never asks to resolve a hop that must be secured, since it
/// has no TLS.
/// A CANCEL goes where its INVITE went, without a resolution (RFC 3261
/// section 9.1).
pub trait Resolve: Send + Sync + 'static {
    /// Resolves `query.uri()` for a request of `query.size()` bytes.
    fn resolve(
        &self,
        query: &Query,
    ) -> impl Future<Output = Result<Target, ResolveError>> + Send;
}

/// Prepares the answer that the ACK of a 2xx owes when the 2xx carried an
/// offer.
///
/// An INVITE sent without an offer, from [`InvitePlan::without_offer`] or
/// [`ReinvitePlan::without_offer`], gets an offer in the 2xx of each fork,
/// and its ACK has to carry the answer (RFC 3261 section 13.2.1). The UA
/// does not read session descriptions, so it cannot make one. It asks for it
/// here, and the ACK waits for it. This is the contract:
///
/// * The answer is a valid answer to the offer, by the rules of RFC 3264.
///   The UA puts it in the ACK as it is, and the same one in every copy of
///   the ACK. It never looks inside.
/// * An [`Offer`] without a session is that of a dialog the UA ends with a
///   BYE after the ACK, such as a fork beyond [`Config::max_forks`] or one of
///   an attempt given up. Its answer should reject every stream, as RFC 3264
///   section 6 lets an answerer do with a port of zero, so that the ACK
///   still completes the exchange.
/// * It runs apart from the UA's other work, as a task of its own, with at
///   most [`Config::max_answers`] at once. An answer is due
///   [`Config::answer_timeout`] after the 2xx asked for it, the wait for a
///   free task included. It is not for anything that waits on the
///   application or a user, since the peer retransmits its 2xx until the
///   ACK.
/// * `None` says that the offer cannot be answered, as one that is not valid
///   SDP. The ACK then goes without an answer, only to stop the 2xx's
///   retransmissions, and the dialog ends with a BYE. That ACK breaks RFC
///   3261 section 13.2.1, so the attempt reports itself degraded, and a
///   session that ends so says [`EndReason::NegotiationFailed`]. Running out
///   of time ends the same way.
pub trait Negotiate: Send + Sync + 'static {
    /// Prepares the answer to `offer`, or returns `None` if there is none.
    fn answer(
        &self,
        offer: &Offer,
    ) -> impl Future<Output = Option<Description>> + Send;
}

/// An offer in a 2xx, which a [`Negotiate`] is asked to answer.
#[derive(Clone, Debug)]
pub struct Offer {
    description: Description,
    session: Option<Session>,
}

impl Offer {
    /// The offer, as the 2xx carried it.
    pub fn description(&self) -> &Description {
        &self.description
    }

    /// The session the 2xx formed or, for a re-INVITE, renegotiates, or
    /// `None` for a dialog the UA ends with a BYE after the ACK, whose answer
    /// should reject the offer.
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }
}

/// The [`Negotiate`] of a UA without one, as [`Config::new`] makes it.
///
/// It has no values. A UA with it never asks for an answer, and refuses an
/// [`InvitePlan`] without an offer.
#[derive(Clone, Copy, Debug)]
pub enum NoNegotiator {}

impl Negotiate for NoNegotiator {
    fn answer(
        &self,
        _offer: &Offer,
    ) -> impl Future<Output = Option<Description>> + Send {
        // A `NoNegotiator` has no values, so this never runs.
        std::future::ready(None)
    }
}

/// What a [`Resolve`] is asked to resolve.
#[derive(Clone, Debug)]
pub struct Query {
    uri: Box<str>,
    size: usize,
}

impl Query {
    /// The SIP URI of the next hop, as RFC 3261 section 8.1.2 picks it.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The encoded size of the request, with room for the Via the endpoint
    /// adds, which can decide the transport (RFC 3261 section 18.1.1). A
    /// request over 1300 bytes then goes over TCP, since the endpoint refuses
    /// it over UDP.
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Resolve for StaticResolver {
    fn resolve(
        &self,
        query: &Query,
    ) -> impl Future<Output = Result<Target, ResolveError>> + Send {
        let result = self
            .resolve_uri(query.uri(), query.size())
            .map(|hop| Target::new(hop.transport, hop.address));
        std::future::ready(result)
    }
}

/// How a UA is set up.
///
/// Every limit has a finite default. A limit of zero counts as one, and one
/// beyond the largest capacity Tokio's channels and semaphores take,
/// [`Semaphore::MAX_PERMITS`], counts as that.
#[derive(Clone, Debug)]
pub struct Config<R = StaticResolver, N = NoNegotiator> {
    contact: Box<str>,
    resolver: R,
    negotiator: Option<N>,
    answers: usize,
    answer_timeout: Duration,
    commands: usize,
    events: usize,
    operations: usize,
    pending_invites: usize,
    attempts: usize,
    dialogs: usize,
    forks: usize,
    cleanups: usize,
    routes: usize,
    jobs: usize,
    resolve_timeout: Duration,
    timers: Timers,
    decision_timeout: Duration,
    invite_bytes: usize,
    description_bytes: usize,
}

/// The Contact URI given to [`Config::new`] is not a SIP or SIPS URI, or has
/// what a Contact that forms a dialog may not have.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidContact(());

impl fmt::Display for InvalidContact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "a Contact URI must be a SIP or SIPS URI without a method or ttl \
             parameter or headers",
        )
    }
}

impl error::Error for InvalidContact {}

/// Keeps a configured limit within what the UA can build, so that
/// [`attach`] cannot fail on it.
fn bounded(limit: usize) -> usize {
    limit.clamp(1, Semaphore::MAX_PERMITS)
}

impl Config {
    /// Creates a configuration whose responses that form a dialog carry
    /// `contact` as their Contact, which RFC 3261 section 12.1.1 requires to
    /// be a SIP or SIPS URI. Next hops resolve through a [`StaticResolver`]
    /// with an empty table.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidContact`] if `contact` is not a SIP or SIPS URI, or
    /// has the `method` or `ttl` parameter or headers, which Table 1 of RFC
    /// 3261 section 19.1.1 does not allow in a Contact that forms a dialog.
    pub fn new(contact: &str) -> Result<Config, InvalidContact> {
        if !allowed_in(contact, Place::Dialog) {
            return Err(InvalidContact(()));
        }

        Ok(Config {
            contact: contact.into(),
            resolver: StaticResolver::new(),
            negotiator: None,
            answers: 64,
            // An answer is local work for an SDP component, and the peer
            // gives up on the ACK 64 T1 after its 2xx, 32 seconds by default.
            answer_timeout: Duration::from_secs(2),
            commands: 256,
            events: 256,
            operations: 1024,
            pending_invites: 256,
            attempts: 256,
            dialogs: 1024,
            forks: 16,
            cleanups: 64,
            routes: 16,
            jobs: 256,
            resolve_timeout: Duration::from_secs(4),
            timers: Timers::new(),
            // A proxy may cancel an INVITE after three minutes without a
            // final response (RFC 3261 section 16.6, Timer C), so a decision
            // later than that is likely to come too late anyway.
            decision_timeout: Duration::from_secs(180),
            invite_bytes: 16 * 1024 * 1024,
            description_bytes: 32 * 1024,
        })
    }
}

impl<R, N> Config<R, N> {
    /// Resolves next hops with `resolver`.
    pub fn resolver<S: Resolve>(self, resolver: S) -> Config<S, N> {
        Config {
            contact: self.contact,
            resolver,
            negotiator: self.negotiator,
            answers: self.answers,
            answer_timeout: self.answer_timeout,
            commands: self.commands,
            events: self.events,
            operations: self.operations,
            pending_invites: self.pending_invites,
            attempts: self.attempts,
            dialogs: self.dialogs,
            forks: self.forks,
            cleanups: self.cleanups,
            routes: self.routes,
            jobs: self.jobs,
            resolve_timeout: self.resolve_timeout,
            timers: self.timers,
            decision_timeout: self.decision_timeout,
            invite_bytes: self.invite_bytes,
            description_bytes: self.description_bytes,
        }
    }

    /// Has `negotiator` prepare the answer that the ACK of a 2xx owes when
    /// the 2xx carried an offer, as [`Negotiate`] describes. Only a UA with
    /// one sends an INVITE without an offer, from
    /// [`InvitePlan::without_offer`].
    pub fn negotiator<M: Negotiate>(self, negotiator: M) -> Config<R, M> {
        Config {
            contact: self.contact,
            resolver: self.resolver,
            negotiator: Some(negotiator),
            answers: self.answers,
            answer_timeout: self.answer_timeout,
            commands: self.commands,
            events: self.events,
            operations: self.operations,
            pending_invites: self.pending_invites,
            attempts: self.attempts,
            dialogs: self.dialogs,
            forks: self.forks,
            cleanups: self.cleanups,
            routes: self.routes,
            jobs: self.jobs,
            resolve_timeout: self.resolve_timeout,
            timers: self.timers,
            decision_timeout: self.decision_timeout,
            invite_bytes: self.invite_bytes,
            description_bytes: self.description_bytes,
        }
    }

    /// Sets how many answers the [`Negotiate`] may prepare at once. More
    /// wait their turn. The default is 64.
    pub fn max_answers(mut self, limit: usize) -> Config<R, N> {
        self.answers = bounded(limit);
        self
    }

    /// Sets how long an answer may take, from the 2xx that asks for it,
    /// with the wait for one of [`Config::max_answers`] included, so that
    /// answers that hang delay no other beyond it. One that takes longer
    /// counts as none, so the ACK goes without it, and the dialog ends. The
    /// default is 2 seconds, well within the 32 seconds a peer with the
    /// default T1 waits for the ACK. A timeout too long to add to the clock,
    /// such as [`Duration::MAX`], sets no deadline.
    pub fn answer_timeout(mut self, timeout: Duration) -> Config<R, N> {
        self.answer_timeout = timeout;
        self
    }

    /// Sets how many submitted operations may wait for the driver. A
    /// submission beyond it gets [`Error::Busy`]. The default is 256.
    pub fn command_capacity(mut self, capacity: usize) -> Config<R, N> {
        self.commands = bounded(capacity);
        self
    }

    /// Sets how many events may wait in [`UaEvents`]. The default is 256.
    ///
    /// Each INVITE this UA sends sets one more place aside, for its
    /// [`Event::AttemptEnded`], so that the end of an attempt cannot be lost
    /// and INVITEs in flight do not crowd out other events. An incoming
    /// INVITE that finds no place gets a 503. Once delivered, each event
    /// holds its place until it is received.
    pub fn event_capacity(mut self, capacity: usize) -> Config<R, N> {
        self.events = bounded(capacity);
        self
    }

    /// Sets how many operations may run at once. A submission beyond it
    /// gets [`Error::Busy`]. An operation's place comes back once its outcome
    /// is in, whether or not its [`Operation`] has been polled. The default
    /// is 1024.
    pub fn max_operations(mut self, limit: usize) -> Config<R, N> {
        self.operations = bounded(limit);
        self
    }

    /// Sets how many incoming INVITEs may wait for a decision. Each counts
    /// until the application submits a decision or drops its
    /// [`IncomingInvite`], also after the UA answered it at the decision
    /// timeout. Beyond it, the UA answers a new INVITE with a 503. The default
    /// is 256.
    ///
    /// An accepted INVITE is kept until its ACK, apart from this limit and
    /// [`Config::max_attempts`]. [`Config::max_dialogs`] bounds those.
    pub fn max_pending_invites(mut self, limit: usize) -> Config<R, N> {
        self.pending_invites = bounded(limit);
        self
    }

    /// Sets how many INVITEs this UA may have sent and still collect
    /// responses for. An INVITE beyond it fails with
    /// [`Error::CapacityExceeded`], and nothing is sent. The default is 256.
    pub fn max_attempts(mut self, limit: usize) -> Config<R, N> {
        self.attempts = bounded(limit);
        self
    }

    /// Sets how many dialogs, early or confirmed, the UA keeps. The default
    /// is 1024.
    ///
    /// An accept without room fails with [`Error::CapacityExceeded`], and the
    /// UA answers the INVITE with a 503. A 2xx to an INVITE of this UA's
    /// without room gets its ACK and a BYE, as for [`Config::max_forks`], and
    /// a provisional response without room forms no early dialog.
    pub fn max_dialogs(mut self, limit: usize) -> Config<R, N> {
        self.dialogs = bounded(limit);
        self
    }

    /// Sets how many dialogs the responses to one INVITE this UA sent may
    /// form and the UA keep, early or confirmed, so that a forking proxy
    /// cannot take the room of every other call. The default is 16.
    ///
    /// A 2xx beyond it forms no session. The UA acknowledges it and ends its
    /// dialog with a BYE, as RFC 3261 section 13.2.2.4 asks of a dialog the
    /// UAC does not want, and the attempt ends incomplete.
    pub fn max_forks(mut self, limit: usize) -> Config<R, N> {
        self.forks = bounded(limit);
        self
    }

    /// Sets how many 2xx responses the UA may hold at once without a
    /// session, to acknowledge them and end their dialogs with a BYE. Each
    /// is held until no more copies of it can arrive. The default is 64.
    ///
    /// They have room of their own, apart from [`Config::max_dialogs`], so
    /// that a fork the UA has no room for still gets its ACK and BYE. Beyond
    /// this limit too, a 2xx gets neither, and the attempt ends degraded.
    pub fn max_cleanups(mut self, limit: usize) -> Config<R, N> {
        self.cleanups = bounded(limit);
        self
    }

    /// Sets how many URIs a dialog's route set may have. A request or
    /// response with more cannot form a dialog. The default is 16.
    pub fn max_routes(mut self, limit: usize) -> Config<R, N> {
        self.routes = bounded(limit);
        self
    }

    /// Sets how many sends, each with the resolution of its next hop, may
    /// run at once, and apart from them how many responses. More wait their
    /// turn. The default is 256.
    ///
    /// The answers to requests the UA keeps nothing for, such as the 503 of
    /// an INVITE it has no room for, wait up to this many more. So do the
    /// answers to a BYE in one of its dialogs or a CANCEL of one of its
    /// INVITEs, apart from them, and they start first, though never more
    /// than eight in a row while other responses wait. A request whose
    /// answer finds no room changes nothing, and the endpoint answers it
    /// with a 500.
    pub fn max_jobs(mut self, limit: usize) -> Config<R, N> {
        self.jobs = bounded(limit);
        self
    }

    /// Sets how long a next hop may take to resolve. A resolution that
    /// takes longer counts as unresolved, so that a resolver that hangs holds
    /// no job for good. The default is 4 seconds.
    pub fn resolve_timeout(mut self, timeout: Duration) -> Config<R, N> {
        self.resolve_timeout = timeout;
        self
    }

    /// Sets T1 and T2, which pace the retransmission of each 2xx the UA sends
    /// and set the deadline for its ACK, 64 T1 later
    /// ([RFC 3261 section 13.3.1.4]). Give the endpoint's timers, so that the
    /// UA and the endpoint agree on them. The default is [`Timers::new`].
    ///
    /// [RFC 3261 section 13.3.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4
    pub fn timers(mut self, timers: Timers) -> Config<R, N> {
        self.timers = timers;
        self
    }

    /// Sets how long the application may take to decide an incoming INVITE.
    /// The UA answers an INVITE still undecided then with a 500, as one whose
    /// [`IncomingInvite`] was dropped. A timeout too long to add to the clock,
    /// such as [`Duration::MAX`], sets no deadline. The default is 3 minutes.
    pub fn decision_timeout(mut self, timeout: Duration) -> Config<R, N> {
        self.decision_timeout = timeout;
        self
    }

    /// Sets how many bytes the incoming INVITEs the UA keeps may take
    /// together. The default is 16 MiB.
    ///
    /// The UA keeps an INVITE from its arrival until its ACK, or until its
    /// final response is sent if that is not a 2xx, and so does an
    /// [`IncomingInvite`] the application keeps. Each INVITE counts its bytes
    /// on the wire, which it keeps apart from the buffer it arrived in. Its
    /// parsed header table comes on top, which the parser bounds to 100 rows.
    /// An INVITE that does not fit gets a 503. Bytes the application copies
    /// out of the INVITE are its own.
    ///
    /// What signa-core keeps of an INVITE is not counted. Until the final
    /// response, its transaction keeps a slice of the INVITE, and with it the
    /// buffer the INVITE arrived in, which over UDP is a chunk of 256 KiB.
    pub fn max_invite_bytes(mut self, bytes: usize) -> Config<R, N> {
        self.invite_bytes = bounded(bytes);
        self
    }

    /// Sets how many bytes a session description the UA receives may take.
    /// The default is 32 KiB.
    ///
    /// A session keeps the last description it got for as long as it lasts,
    /// and its snapshot shows it, so this and [`Config::max_dialogs`] bound
    /// what the sessions keep. An INVITE whose offer is larger gets a 413
    /// (RFC 3261 section 21.4.11). A larger description in a response or an
    /// ACK counts as none, which fails the exchange that needed it, as an
    /// answer missing from a 2xx or an ACK does.
    pub fn max_description_bytes(mut self, bytes: usize) -> Config<R, N> {
        self.description_bytes = bounded(bytes);
        self
    }

    fn limits(&self) -> Limits {
        Limits {
            attempts: self.attempts,
            // An incoming INVITE waits for a decision, and an accepted one
            // for its ACK, which its dialog bounds.
            incoming: self.pending_invites.saturating_add(self.dialogs),
            dialogs: self.dialogs,
            usages: self.dialogs,
            // A replay context outlives its dialog while copies of its 2xx
            // can arrive, so a dialog can leave one behind. Each re-INVITE
            // has one on top, until copies of its 2xx stop.
            replays: self.dialogs.saturating_mul(4),
            forks: self.forks,
            cleanups: self.cleanups,
            routes: self.routes,
            operations: self.operations,
            // The driver runs each command as it arrives.
            commands: 1,
            // A dialog has one re-INVITE open at a time, either way, and
            // the record of one this UA sent outlives its final response
            // while copies of its 2xx can come, so twice as many.
            reinvites: self.dialogs.saturating_mul(2),
            t1: self.timers.t1(),
            t2: self.timers.t2(),
            decision_timeout: self.decision_timeout,
        }
    }
}

/// Why [`attach`] refused an endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AttachError {
    /// The endpoint has stateless reception, which creates no transactions
    /// for the UA to answer in.
    Stateless,
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttachError::Stateless => {
                f.write_str("a UA needs an endpoint with stateful reception")
            }
        }
    }
}

impl error::Error for AttachError {}

/// The parts of a running UA.
#[derive(Debug)]
pub struct Ua {
    /// Submits operations. It can be cloned.
    pub handle: UaHandle,
    /// Receives events.
    pub events: UaEvents,
    /// Runs the UA once polled.
    pub driver: UaDriver,
}

/// Starts a UA on a dedicated endpoint.
///
/// The UA takes `incoming`, the endpoint's only receiver, so nothing else
/// receives the endpoint's requests. Its driver answers what the application
/// does not, and ACK and CANCEL never wait on the application. It returns
/// the three parts of a UA:
///
/// * [`UaHandle`] submits operations, such as sending an INVITE.
/// * [`UaEvents`] receives what the application decides on, such as an
///   [`IncomingInvite`], and notifications about sessions.
/// * [`UaDriver`] is a future that runs the UA. Nothing happens until it is
///   polled, and dropping it stops the UA at once.
///
/// # Submitting
///
/// Every operation is submitted synchronously, through a method whose name
/// starts with `try_`. It either takes the operation, or refuses it with a
/// [`SubmitError`] that hands back everything it was given, such as the
/// authority to decide an incoming INVITE. A refused operation changed nothing
/// and sent nothing. A taken one goes on whatever happens to its [`Operation`],
/// the future of its outcome. Dropping that future does not withdraw it.
///
/// # Events
///
/// Events arrive in order through a bounded queue. No [`IncomingInvite`] is
/// lost unanswered. The UA answers an INVITE it has no room to report with a
/// 503, as it does once [`UaEvents`] is dropped. A notification that does not
/// fit is dropped and counted, and the count comes as [`Event::Lagged`] as soon
/// as there is room. Nothing the protocol needs is lost with it. The outcome
/// of an operation comes through its [`Operation`], and the state of a session
/// through [`UaHandle::snapshot`].
///
/// # Shutting down
///
/// [`UaHandle::shutdown`] stops the UA in two phases. The UA stops taking new
/// work and ends what is under way, or lets the application end it, while
/// its endpoint keeps taking the requests that work needs. Then it shuts the
/// endpoint down, and the driver returns once both have stopped or the
/// deadline came. Dropping the driver instead is a forced stop.
///
/// Shut the endpoint down through the UA, not through another handle of it.
/// While the UA has work, a session up included, it holds a work guard of
/// the endpoint, so a shutdown of the endpoint alone waits for its deadline.
/// And once the endpoint shuts down, it refuses the BYE that ends a session,
/// which is a new transaction. The driver then returns once the endpoint
/// stops, with [`ShutdownOutcome::EndpointLost`].
///
/// # Dropping
///
/// Dropping a handle sends nothing. A [`Session`] or [`InviteAttempt`] going
/// away is neither a BYE nor a CANCEL, and the UA keeps answering and
/// acknowledging for it. The application ends them with
/// [`UaHandle::try_terminate`], [`UaHandle::try_cancel`] and
/// [`UaHandle::try_abandon`], or all at once with a
/// [`ShutdownMode::Terminate`] shutdown. The UA sends a BYE of its own only
/// for a dialog it cannot keep or that cannot go on, such as a fork beyond
/// its limits or a session whose ACK never came.
///
/// The exception is an [`IncomingInvite`] dropped without a decision.
/// Nobody can answer it any more, so the UA does, with a 500.
///
/// # Errors
///
/// Returns [`AttachError::Stateless`] for an endpoint with stateless
/// reception.
pub fn attach<R: Resolve, N: Negotiate>(
    endpoint: Endpoint,
    incoming: Incoming,
    config: Config<R, N>,
) -> Result<Ua, AttachError> {
    if endpoint.reception() != Reception::Stateful {
        return Err(AttachError::Stateless);
    }

    let (commands, command_receiver) = mpsc::channel(config.commands);
    // The places of the attempts' last events come on top of the others.
    let capacity = bounded(config.events.saturating_add(config.attempts));
    let (events, event_receiver) = mpsc::channel(capacity);
    let (shutdown, requests) = watch::channel(ShutdownRequest::default());
    let (reports, report_receiver) = watch::channel(None);
    let shared = Arc::new(Shared {
        id: UaId(NEXT_UA.fetch_add(1, Ordering::Relaxed)),
        late_offer: config.negotiator.is_some(),
        commands,
        operations: Arc::new(Semaphore::new(config.operations)),
        shutdown,
        reports: report_receiver,
    });
    let driver = driver::Driver::new(
        endpoint,
        incoming,
        config,
        shared.clone(),
        command_receiver,
        events,
        (requests, reports),
    );

    Ok(Ua {
        handle: UaHandle { shared },
        events: UaEvents { receiver: event_receiver },
        driver: UaDriver { future: Box::pin(driver.run()) },
    })
}

/// Tells the handles of one UA from those of another.
///
/// Each UA numbers its sessions and attempts from the same start, so a key
/// alone would name another UA's session as well. A handle carries the
/// identity of the UA that made it, and every other UA refuses it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UaId(u64);

/// The next UA's identity. 2^64 UAs in one process will not happen.
static NEXT_UA: AtomicU64 = AtomicU64::new(0);

/// What the handles share with the driver.
#[derive(Debug)]
struct Shared {
    id: UaId,
    /// Whether the UA has a [`Negotiate`], and so sends INVITEs without an
    /// offer.
    late_offer: bool,
    commands: mpsc::Sender<Command>,
    /// One permit per operation that runs. A submission takes one, so that
    /// the driver always has room for what it admitted.
    operations: Arc<Semaphore>,
    /// The shutdown asked for so far, which every call to
    /// [`UaHandle::shutdown`] merges into.
    shutdown: watch::Sender<ShutdownRequest>,
    /// The report of the stop, once the driver has made it.
    reports: watch::Receiver<Option<ShutdownReport>>,
}

/// The shutdown asked for so far: the strongest mode and the earliest
/// deadline of every call.
#[derive(Clone, Copy, Debug, Default)]
struct ShutdownRequest {
    mode: Option<ShutdownMode>,
    /// `None` once asked for is no deadline, from a timeout too long to add
    /// to the clock.
    deadline: Option<Instant>,
}

/// What a handle asks of the driver.
#[derive(Debug)]
enum Command {
    Operation {
        command: model::Command,
        reply: oneshot::Sender<Result<Completion, Error>>,
        permit: OwnedSemaphorePermit,
    },
    Snapshot {
        usage: UsageKey,
        reply: oneshot::Sender<Option<SessionSnapshot>>,
    },
    AttemptSnapshot {
        attempt: AttemptKey,
        reply: oneshot::Sender<Option<AttemptSnapshot>>,
    },
}

/// Submits an operation on a handle the application keeps, which has
/// nothing to hand back if it is refused. A handle of another UA, `ua`, is
/// refused before anything is admitted.
fn submit_on<T>(
    shared: &Arc<Shared>,
    ua: UaId,
    command: model::Command,
) -> Result<Operation<T>, SubmitError<()>> {
    if ua != shared.id {
        return Err(SubmitError {
            error: Error::InvalidInput,
            value: Box::new(()),
        });
    }
    shared.submit((), |()| command)
}

impl Shared {
    /// Takes a slot in the command queue and an operation permit, or
    /// neither.
    fn admit(
        &self,
    ) -> Result<(mpsc::Permit<'_, Command>, OwnedSemaphorePermit), Error> {
        let slot =
            self.commands.try_reserve().map_err(|error| match error {
                mpsc::error::TrySendError::Full(()) => Error::Busy,
                mpsc::error::TrySendError::Closed(()) => Error::Closed,
            })?;
        let permit = self
            .operations
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        Ok((slot, permit))
    }

    /// Submits `command` as an operation, or hands back `value` with why
    /// not. `command` is only built once the operation is admitted.
    fn submit<T, V>(
        self: &Arc<Shared>,
        value: V,
        command: impl FnOnce(V) -> model::Command,
    ) -> Result<Operation<T>, SubmitError<V>> {
        let (slot, permit) = match self.admit() {
            Ok(admitted) => admitted,
            Err(error) => {
                return Err(SubmitError { error, value: Box::new(value) });
            }
        };

        let (reply, receiver) = oneshot::channel();
        slot.send(Command::Operation {
            command: command(value),
            reply,
            permit,
        });
        Ok(Operation { receiver, ua: self.id, kind: PhantomData })
    }
}

/// Submits operations to a UA.
#[derive(Clone, Debug)]
pub struct UaHandle {
    shared: Arc<Shared>,
}

impl UaHandle {
    /// Submits an initial INVITE, built from `plan` with the offer it
    /// carries, or without one for a UA with a [`Negotiate`].
    ///
    /// The UA picks the Call-ID, the From tag and the first CSeq number, adds
    /// its Contact, resolves the next hop from the first route or the
    /// Request-URI (RFC 3261 section 8.1.2), and hands the INVITE to the
    /// endpoint. The operation completes once the endpoint has it, with the
    /// [`InviteAttempt`] that collects its responses.
    ///
    /// Each dialog a response forms comes as an event, and the UA
    /// acknowledges each 2xx itself, whatever the application does with the
    /// session. Without an offer, the ACK of each 2xx carries the answer to
    /// its offer that the [`Negotiate`] prepared. No 2xx wins over another.
    /// The UA keeps each one as a session of its own.
    /// [`Event::AttemptEnded`] says what the INVITE came to once no more
    /// responses can arrive, and [`UaHandle::attempt_snapshot`] says it
    /// before.
    ///
    /// The operation fails, with nothing sent unless the error says so:
    ///
    /// * with [`Error::Unroutable`] when the next hop does not resolve or
    ///   needs TLS,
    /// * with [`Error::CapacityExceeded`] when the UA has no room for the
    ///   attempt, or none for its last event because the application lets
    ///   the events pile up,
    /// * with [`Error::TransportFailure`] when the endpoint could not open a
    ///   connection or write the INVITE,
    /// * with [`Error::CoreSubmissionRejected`] when the endpoint refuses the
    ///   INVITE, as when it is busy or the resolver picked UDP for one too
    ///   large for it,
    /// * with [`Error::Internal`] when the UA has no randomness for the
    ///   INVITE's identifiers, or the resolver panicked,
    /// * with [`Error::DriverStopped`] when the endpoint stops first, and
    /// * with [`Error::InvalidInput`] when the endpoint refuses the INVITE as
    ///   malformed, which would be a bug of the UA.
    ///
    /// # Errors
    ///
    /// Returns `plan` with [`Error::InvalidInput`] when the UA cannot send
    /// it, as [`InvitePlan`] says, or when it has no offer and the UA no
    /// [`Negotiate`], with [`Error::Busy`] when the command queue or the
    /// operations are full, and with [`Error::Closed`] once the UA shuts
    /// down or the driver has stopped. An INVITE submitted just before a
    /// shutdown fails with [`Error::Closed`] too, with nothing sent.
    pub fn try_invite(
        &self,
        plan: InvitePlan,
    ) -> Result<Operation<InviteAttempt>, SubmitError<InvitePlan>> {
        if !plan.is_valid() || (!plan.has_offer() && !self.shared.late_offer) {
            return Err(SubmitError {
                error: Error::InvalidInput,
                value: Box::new(plan),
            });
        }
        if self.shared.shutdown.borrow().mode.is_some() {
            return Err(SubmitError {
                error: Error::Closed,
                value: Box::new(plan),
            });
        }

        self.shared.submit(plan, |plan| model::Command::Invite {
            plan: Box::new(plan),
        })
    }

    /// Cancels an INVITE this UA sent, while it has no final response.
    ///
    /// The endpoint sends the CANCEL once a provisional response has come,
    /// and none if a final response comes first (RFC 3261 section 9.1). The
    /// CANCEL is a transaction of its own, whose response the UA does not
    /// wait for. It ends nothing by itself. The INVITE usually ends with a
    /// 487, and [`Event::AttemptEnded`] says so. A 2xx that wins the race
    /// forms a session as any other, which gets its ACK and stays up for the
    /// application to keep or end (section 15). To end such sessions too,
    /// give the attempt up with [`UaHandle::try_abandon`] instead.
    ///
    /// The operation completes once the endpoint has the CANCEL, with
    /// [`CancelResult::Sent`], or once it is clear that none is needed, with
    /// [`CancelResult::NotNeeded`]. It can wait long, for a provisional
    /// response. It fails, with nothing sent unless the error says so:
    ///
    /// * with [`Error::InvalidTransition`] if a CANCEL was already asked
    ///   for, by this or by [`UaHandle::try_abandon`],
    /// * with [`Error::StaleDecision`] once the attempt has ended,
    /// * with [`Error::CoreSubmissionRejected`] or
    ///   [`Error::TransportFailure`] when the endpoint needed a new
    ///   connection to the next hop and could not admit or open one, and
    /// * with [`Error::DriverStopped`] when the endpoint stops first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] for an attempt of another UA,
    /// [`Error::Busy`] when the command queue or the operations are full, and
    /// [`Error::Closed`] once the driver has stopped.
    pub fn try_cancel(
        &self,
        attempt: &InviteAttempt,
    ) -> Result<Operation<CancelResult>, SubmitError<()>> {
        let AttemptId { ua, attempt } = attempt.id;
        submit_on(&self.shared, ua, model::Command::Cancel { attempt })
    }

    /// Gives up an INVITE this UA sent, as a caller that hangs up does
    /// (RFC 3261 section 15).
    ///
    /// The INVITE gets its CANCEL, as with [`UaHandle::try_cancel`], unless
    /// it has a final response or a CANCEL already. Each session it formed
    /// whose dialog is confirmed gets a BYE, as with
    /// [`UaHandle::try_terminate`]. Each early one ends with the INVITE,
    /// which the CANCEL ends, and shows as [`SessionPhase::Ending`] until
    /// then. Each 2xx that comes later, from any fork, gets its ACK and then
    /// a BYE, and forms no session (section 13.2.2.4).
    ///
    /// The operation completes once the UA has done that much, which is
    /// neither the CANCEL nor a BYE reaching the endpoint. Each session says
    /// when it ended, with [`Event::Ended`]. A BYE that cannot reach the
    /// endpoint leaves its session up, for the application to end again.
    /// Giving an attempt up twice does no more than once. The operation
    /// fails with [`Error::StaleDecision`] once the attempt has ended, which
    /// is as late as a 2xx can come for it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] for an attempt of another UA,
    /// [`Error::Busy`] when the command queue or the operations are full, and
    /// [`Error::Closed`] once the driver has stopped.
    pub fn try_abandon(
        &self,
        attempt: &InviteAttempt,
    ) -> Result<Operation<()>, SubmitError<()>> {
        let AttemptId { ua, attempt } = attempt.id;
        submit_on(&self.shared, ua, model::Command::Abandon { attempt })
    }

    /// Ends a session with a BYE.
    ///
    /// The BYE goes in a client transaction of its own, through the
    /// dialog's route set. The session ends once the endpoint has it, with
    /// [`Event::Ended`] and [`EndReason::LocalBye`], before any response,
    /// as RFC 3261 section 15.1.1 has it.
    ///
    /// The BYE waits for an ACK first, and the session shows as
    /// [`SessionPhase::Ending`] meanwhile. A session this UA answered waits
    /// for the ACK of its 2xx, since section 15 keeps the callee from sending
    /// its BYE before that. A session whose ACK waits for the answer of the
    /// [`Negotiate`] waits for that ACK to go. If the ACK of this UA's 2xx
    /// never comes, the BYE goes at the ACK deadline, after
    /// [`Event::AckTimeout`], and the session ends with
    /// [`EndReason::LocalBye`] even if the BYE then cannot reach the
    /// endpoint, since the dialog cannot go on without the ACK.
    ///
    /// The operation completes with the BYE's response. A 2xx is success.
    /// It fails with [`Error::RemoteFailure`] for another final response,
    /// such as the 481 of a peer that ended the dialog already, with
    /// [`Error::Timeout`] if no response came, and with
    /// [`Error::TransportFailure`] if the transaction failed to write. The
    /// session has ended either way, and the UA sends no second BYE.
    ///
    /// When the BYE never reaches the endpoint, the session stays as it
    /// was, but for the ACK deadline above, and the operation fails, with
    /// nothing sent:
    ///
    /// * with [`Error::Unroutable`] when the next hop does not resolve or
    ///   needs TLS,
    /// * with [`Error::CoreSubmissionRejected`] when the endpoint refuses
    ///   the BYE, as when it is busy,
    /// * with [`Error::TransportFailure`] when it could not open a
    ///   connection, and
    /// * with [`Error::InvalidTransition`] when the dialog has run out of
    ///   CSeq numbers.
    ///
    /// It also fails with [`Error::InvalidTransition`] for a session that
    /// is already ending or has ended, and with [`Error::StaleDecision`]
    /// for one the UA has let go of. A peer's BYE that crosses this one
    /// ends the session too, and an operation still waiting for the ACK then
    /// completes with nothing sent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] for a session of another UA,
    /// [`Error::Busy`] when the command queue or the operations are full, and
    /// [`Error::Closed`] once the driver has stopped.
    pub fn try_terminate(
        &self,
        session: &Session,
    ) -> Result<Operation<()>, SubmitError<()>> {
        let SessionId { ua, usage } = session.id;
        submit_on(&self.shared, ua, model::Command::Terminate { usage })
    }

    /// Sends a re-INVITE in the dialog of a session, to change it with the
    /// offer of `plan`, or without one for a UA with a [`Negotiate`] (RFC
    /// 3261 section 14).
    ///
    /// The UA builds the re-INVITE from the dialog, with the next CSeq
    /// number, and sends it through the route set. A session takes one
    /// re-INVITE at a time, and none while an INVITE of either side waits
    /// for its final response or its ACK, or an offer waits for its answer
    /// (section 14.1).
    ///
    /// Nothing about the session changes until a 2xx comes, and then the
    /// operation completes once the new offer/answer exchange is complete:
    /// the 2xx brought the answer, or, without an offer, the [`Negotiate`]
    /// prepared the answer to the 2xx's offer for the ACK. The session's
    /// snapshot then has what the peer sent, and a higher
    /// [`SessionSnapshot::session_revision`]. This is the point to apply the
    /// new session, and not before. An offer that was only prepared can be
    /// dropped on any failure, since the session stays as it was then (RFC
    /// 3261 section 14.1, RFC 6141 section 3). The 2xx also replaces the
    /// remote target with its Contact, which
    /// [`SessionSnapshot::target_revision`] counts. That happens at the 2xx,
    /// apart from the session, and stays if the exchange then fails (RFC
    /// 6141 section 4).
    ///
    /// If the peer has a re-INVITE of its own pending, it answers with a
    /// 491, and the UA sends the re-INVITE once more after a random wait of
    /// 2.1 to 4 seconds if this UA made the call, or up to 2 seconds if it
    /// took it, as section 14.1 has it. The second try gets a new CSeq
    /// number and transaction. It does not go if the session changed in
    /// between, is ending, or is busy with another exchange, and a 491 to it
    /// is final. The operation then fails with the 491, for the application
    /// to decide again.
    ///
    /// The operation fails, with the session as it was unless the error
    /// says otherwise:
    ///
    /// * with [`Error::RemoteFailure`] for a final response other than a
    ///   2xx, such as a 488 for an offer the peer does not take. A 481 ends
    ///   the session, since the peer has no such dialog, and a 408 ends it
    ///   with a BYE ([`EndReason::ReinviteFailed`]),
    /// * with [`Error::Timeout`] when no response came, which ends the
    ///   session with a BYE too (sections 12.2.1.2 and 14.1),
    /// * with [`Error::NegotiationFailure`] when the 2xx lacked the answer or
    ///   offer it owed, or no answer could be had for its offer. The UA then
    ///   ends the session with a BYE after the ACK, as for an initial INVITE,
    /// * with [`Error::SessionEnded`] when the session ended first, by a BYE
    ///   either way. A 2xx that comes later still gets its ACK,
    /// * with [`Error::InvalidTransition`], with nothing sent, when the
    ///   session is not established, is ending, or is busy as said above,
    ///   or its dialog has run out of CSeq numbers,
    /// * with [`Error::StaleDecision`] for a session the UA has let go of,
    /// * with [`Error::CapacityExceeded`] when the UA has no room for the
    ///   re-INVITE, and
    /// * as [`UaHandle::try_invite`] fails when the re-INVITE never reaches
    ///   the endpoint, or with [`Error::TransportFailure`] when its
    ///   transaction failed to write.
    ///
    /// The UA does not cancel a re-INVITE of its own.
    ///
    /// # Errors
    ///
    /// Returns `plan` with [`Error::InvalidInput`] for a session of another
    /// UA, an offer without a body, or no offer for a UA without a
    /// [`Negotiate`], with [`Error::Busy`] when the command queue or the
    /// operations are full, and with [`Error::Closed`] once the driver has
    /// stopped.
    pub fn try_reinvite(
        &self,
        session: &Session,
        plan: ReinvitePlan,
    ) -> Result<Operation<()>, SubmitError<ReinvitePlan>> {
        let SessionId { ua, usage } = session.id;
        if ua != self.shared.id
            || !plan.is_valid()
            || (!plan.has_offer() && !self.shared.late_offer)
        {
            return Err(SubmitError {
                error: Error::InvalidInput,
                value: Box::new(plan),
            });
        }

        self.shared.submit(plan, |plan| model::Command::Reinvite {
            usage,
            offer: plan.into_offer(),
        })
    }

    /// Returns what an INVITE this UA sent has come to so far, or `None` once
    /// it has ended and [`Event::AttemptEnded`] has said what it came to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] for a handle of another UA,
    /// [`Error::Busy`] when the command queue is full, [`Error::Closed`] when
    /// the driver no longer takes commands, and [`Error::DriverStopped`] when
    /// it stopped before answering.
    pub async fn attempt_snapshot(
        &self,
        attempt: &InviteAttempt,
    ) -> Result<Option<AttemptSnapshot>, Error> {
        let AttemptId { ua, attempt } = attempt.id;
        if ua != self.shared.id {
            return Err(Error::InvalidInput);
        }
        let slot =
            self.shared.commands.try_reserve().map_err(
                |error| match error {
                    mpsc::error::TrySendError::Full(()) => Error::Busy,
                    mpsc::error::TrySendError::Closed(()) => Error::Closed,
                },
            )?;
        let (reply, receiver) = oneshot::channel();
        slot.send(Command::AttemptSnapshot { attempt, reply });

        receiver.await.map_err(|_| Error::DriverStopped)
    }

    /// Returns where a session stands, or `None` once the UA has let go of
    /// it. A session that ended is still shown, with why, for as long as it
    /// is among the last [`Config::max_dialogs`] sessions to end.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] for a handle of another UA,
    /// [`Error::Busy`] when the command queue is full, [`Error::Closed`] when
    /// the driver no longer takes commands, and [`Error::DriverStopped`] when
    /// it stopped before answering.
    pub async fn snapshot(
        &self,
        session: &Session,
    ) -> Result<Option<SessionSnapshot>, Error> {
        let SessionId { ua, usage } = session.id;
        if ua != self.shared.id {
            return Err(Error::InvalidInput);
        }
        let slot =
            self.shared.commands.try_reserve().map_err(
                |error| match error {
                    mpsc::error::TrySendError::Full(()) => Error::Busy,
                    mpsc::error::TrySendError::Closed(()) => Error::Closed,
                },
            )?;
        let (reply, receiver) = oneshot::channel();
        slot.send(Command::Snapshot { usage, reply });

        receiver.await.map_err(|_| Error::DriverStopped)
    }

    /// Shuts the UA down, and then its endpoint, within `timeout`, and
    /// returns a future of the report.
    ///
    /// The UA stops taking new work at once. [`UaHandle::try_invite`] fails
    /// with [`Error::Closed`], and a new initial INVITE gets a 503, which RFC
    /// 3261 section 21.5.4 gives a server down for maintenance. The endpoint
    /// keeps taking requests meanwhile, so that what is under way goes on: a
    /// BYE or a re-INVITE in a session, a CANCEL, the ACK of a 2xx, copies of
    /// a 2xx, and the answers [`Negotiate`] prepares. What happens to the
    /// work under way depends on `mode`, see [`ShutdownMode`].
    ///
    /// Once the UA has nothing left to do, it lets go of what held the
    /// endpoint's drain for it, and shuts the endpoint down with the time
    /// that is left. The endpoint then refuses new requests with a 503, and
    /// drains what it holds, such as an INVITE transaction that took a 2xx,
    /// until Timer L. The driver keeps answering what the endpoint still
    /// delivers until it has stopped, then ends every task of the UA and
    /// returns. [`ShutdownReport`] says how it went.
    ///
    /// The UA does not wait for the endpoint before its own work is done,
    /// since a session it ends needs a BYE, a new transaction the endpoint
    /// refuses once it shuts down. An INVITE this UA sent can get the 2xx of
    /// another fork until Timer M, 64 T1 after its first 2xx, which needs an
    /// ACK and may need a BYE, so the UA waits for that too.
    ///
    /// # Deadline
    ///
    /// `timeout` counts from this call, for the UA and the endpoint
    /// together. The phases share it, and no phase starts it again. A
    /// `timeout` too long to add to the clock, such as [`Duration::MAX`],
    /// sets no deadline. At the deadline the endpoint stops at once and
    /// sends nothing more, and the UA lets go of what it had left. Each
    /// operation still running fails with [`Error::DriverStopped`].
    ///
    /// Calling this again, on any handle of the UA, joins the same shutdown.
    /// The earliest deadline holds, and a later call cannot extend it. A
    /// call with [`ShutdownMode::Terminate`] makes a drain a termination,
    /// and a call with [`ShutdownMode::DrainExisting`] changes nothing back.
    ///
    /// # Cancellation
    ///
    /// The shutdown starts when this is called. Dropping the future gives up
    /// the wait, not the shutdown, and does not move the deadline. Nothing
    /// happens unless the [`UaDriver`] runs, though.
    pub fn shutdown(
        &self,
        mode: ShutdownMode,
        timeout: Duration,
    ) -> UaShutdown {
        // A deadline past the clock is none. One that only far exceeds any
        // deadline the UA means falls back to the far future, as its timers
        // do.
        let now = Instant::now();
        let deadline =
            now.checked_add(timeout).or_else(|| now.checked_add(timer::FAR));
        self.shared.shutdown.send_modify(|request| {
            request.mode = request.mode.max(Some(mode));
            request.deadline = match (request.deadline, deadline) {
                (Some(earlier), Some(later)) => Some(earlier.min(later)),
                (earlier, later) => earlier.or(later),
            };
        });

        UaShutdown::new(self.shared.reports.clone())
    }
}

/// How [`UaHandle::shutdown`] treats the work under way.
///
/// Both modes stop new work at once, and neither stops what RFC 3261 asks to
/// finish, such as the ACK of a 2xx or a 200 to a BYE. They differ in who
/// ends the sessions. A later call can turn a drain into a termination,
/// never the other way.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum ShutdownMode {
    /// Lets the application end the work under way. Sessions stay up, and
    /// the application may still decide the INVITEs it holds, end sessions,
    /// and send or take re-INVITEs in them. An INVITE this UA sent goes on
    /// collecting responses, and a 2xx of another fork forms a session as
    /// before. The shutdown completes once all of it has ended, or at the
    /// deadline.
    DrainExisting,
    /// Ends the work under way, as a user who hangs up would (RFC 3261
    /// section 15):
    ///
    /// * An INVITE the application has not decided gets a 503. A decision
    ///   the application submits then finds the final taken.
    /// * An INVITE this UA sent is given up, as with
    ///   [`UaHandle::try_abandon`]: a CANCEL while it has no final response,
    ///   and an ACK and a BYE for each 2xx that comes later.
    /// * Every session gets a BYE, a callee's after the ACK of its 2xx, and
    ///   ends with [`EndReason::Shutdown`]. A re-INVITE the peer sent in it
    ///   that waits for a decision gets a 487 once the BYE goes, as RFC 3261
    ///   section 15.1.2 recommends when the peer's BYE leaves one pending,
    ///   and a new one a 491, since the session is ending. A re-INVITE this
    ///   UA sent goes on, since the UA does not cancel its own, and one the
    ///   peer never answers holds the shutdown until its deadline.
    ///
    /// None of this takes an operation of the application's, so it goes
    /// whatever the limit of [`Config::max_operations`]. The BYEs start
    /// behind the UA's other requests, such as the ACK of a 2xx, though
    /// never more than eight of those in a row while one waits.
    Terminate,
}

/// How a UA stopped, as [`ShutdownReport::outcome`] says.
///
/// This is signa-ua's lifecycle contract, not something an RFC defines.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ShutdownOutcome {
    /// Everything the UA had taken on ended before the deadline, and then
    /// the endpoint drained too. No transaction, timer, task or write of
    /// either is left, and nothing goes out after the report.
    ///
    /// It does not say that the peers received anything, nor that each call
    /// ended well. A BYE may have got a 481 or no answer, which
    /// [`ShutdownReport::failed_byes`] counts.
    Drained,
    /// The deadline came first, for the UA or for the endpoint. The endpoint
    /// stopped at once, and the UA let go of what it had left, which the
    /// report counts.
    DeadlineExpired,
    /// The endpoint stopped before the UA was done, as when another of its
    /// handles shut it down. The UA let go of what it had left, which the
    /// report counts.
    EndpointLost,
}

/// What a UA's stop came to, as [`UaShutdown`] reports it.
///
/// The counts of sessions that ended cover the time from the first call of
/// [`UaHandle::shutdown`] to the stop. What was left counts at the stop, and
/// is nothing when the UA drained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ShutdownReport {
    /// How the UA stopped.
    pub outcome: ShutdownOutcome,
    /// The sessions that ended during the shutdown, whatever ended them.
    pub ended: usize,
    /// Of those, the sessions the UA ended for [`ShutdownMode::Terminate`].
    pub terminated: usize,
    /// The BYEs of sessions during the shutdown that got no 2xx: those the
    /// endpoint never took, and those that got another final response or
    /// none. The peer may still have such a session.
    pub failed_byes: usize,
    /// The sessions still up when the UA stopped. The peers still have
    /// them.
    pub sessions_left: usize,
    /// The INVITEs the UA still held when it stopped: those it received
    /// without a final response the endpoint took, those it sent whose
    /// responses it still collected, and the re-INVITEs it sent without a
    /// final response.
    pub invites_left: usize,
    /// The operations still running when the UA stopped, which failed with
    /// [`Error::DriverStopped`].
    pub operations_failed: usize,
}

/// Resolves with the report of a UA's stop.
///
/// [`UaHandle::shutdown`] returns it. Every caller gets the same report.
/// Dropping it before it resolves gives up the wait, not the shutdown.
///
/// It resolves with [`Error::DriverStopped`] if the [`UaDriver`] is dropped
/// before it stops, which is a forced stop without a report.
pub struct UaShutdown {
    done: Pin<
        Box<dyn Future<Output = Result<ShutdownReport, Error>> + Send + Sync>,
    >,
}

impl UaShutdown {
    fn new(
        mut reports: watch::Receiver<Option<ShutdownReport>>,
    ) -> UaShutdown {
        UaShutdown {
            done: Box::pin(async move {
                loop {
                    if let Some(report) = *reports.borrow_and_update() {
                        return Ok(report);
                    }
                    if reports.changed().await.is_err() {
                        return (*reports.borrow())
                            .ok_or(Error::DriverStopped);
                    }
                }
            }),
        }
    }
}

impl Future for UaShutdown {
    type Output = Result<ShutdownReport, Error>;

    fn poll(
        mut self: Pin<&mut UaShutdown>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ShutdownReport, Error>> {
        self.done.as_mut().poll(cx)
    }
}

impl fmt::Debug for UaShutdown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UaShutdown")
    }
}

/// An operation the UA refused, with what was submitted.
///
/// The value is boxed, so that a `Result` holding this stays small on the
/// path where nothing is refused.
pub struct SubmitError<T> {
    error: Error,
    value: Box<T>,
}

impl<T> SubmitError<T> {
    /// Returns why the operation was refused.
    pub fn error(&self) -> Error {
        self.error
    }

    /// Returns what was submitted, as it was.
    pub fn into_inner(self) -> T {
        *self.value
    }
}

impl<T> fmt::Debug for SubmitError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubmitError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<T> fmt::Display for SubmitError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "operation refused: {}", self.error)
    }
}

impl<T> error::Error for SubmitError<T> {}

/// The outcome of a submitted operation.
///
/// It resolves once the operation has ended. Dropping it withdraws nothing.
/// The operation goes on to its outcome, which nobody reads then.
#[must_use = "an operation goes on without its future, but its outcome is lost"]
pub struct Operation<T> {
    receiver: oneshot::Receiver<Result<Completion, Error>>,
    /// The UA that runs it, for the handle it completes with.
    ua: UaId,
    kind: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for Operation<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Operation")
    }
}

impl<T> Operation<T> {
    fn poll_completion(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Completion, Error>> {
        Pin::new(&mut self.receiver)
            .poll(cx)
            .map(|outcome| outcome.unwrap_or(Err(Error::DriverStopped)))
    }
}

impl Future for Operation<InviteAttempt> {
    type Output = Result<InviteAttempt, Error>;

    fn poll(
        mut self: Pin<&mut Operation<InviteAttempt>>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<InviteAttempt, Error>> {
        let ua = self.ua;
        self.poll_completion(cx).map(|outcome| match outcome? {
            Completion::Attempt(attempt) => {
                Ok(InviteAttempt { id: AttemptId { ua, attempt } })
            }
            _ => unreachable!("an INVITE completes with its attempt"),
        })
    }
}

impl Future for Operation<Session> {
    type Output = Result<Session, Error>;

    fn poll(
        mut self: Pin<&mut Operation<Session>>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Session, Error>> {
        let ua = self.ua;
        self.poll_completion(cx).map(|outcome| match outcome? {
            Completion::Session(usage) => Ok(Session::new(ua, usage)),
            _ => unreachable!("an accept completes with its session"),
        })
    }
}

impl Future for Operation<CancelResult> {
    type Output = Result<CancelResult, Error>;

    fn poll(
        mut self: Pin<&mut Operation<CancelResult>>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<CancelResult, Error>> {
        self.poll_completion(cx).map(|outcome| match outcome? {
            Completion::Cancel(result) => Ok(result),
            _ => unreachable!("a cancel completes with what it did"),
        })
    }
}

impl Future for Operation<()> {
    type Output = Result<(), Error>;

    fn poll(
        mut self: Pin<&mut Operation<()>>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        self.poll_completion(cx).map(|outcome| outcome.map(drop))
    }
}

/// Receives a UA's events.
#[derive(Debug)]
pub struct UaEvents {
    receiver: mpsc::Receiver<Event>,
}

impl UaEvents {
    /// Receives the next event, or `None` once the driver has stopped and
    /// every event has been received.
    ///
    /// It is cancellation-safe. Dropping the future loses no event.
    pub async fn recv(&mut self) -> Option<Event> {
        self.receiver.recv().await
    }
}

/// Something the application decides on or is told.
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    /// An initial INVITE waits for a decision.
    Invite(IncomingInvite),
    /// A re-INVITE in the dialog of a session waits for a decision, as an
    /// initial INVITE does. [`IncomingInvite::session`] names the session.
    Reinvite(IncomingInvite),
    /// A provisional response to an INVITE this UA sent formed an early
    /// dialog.
    #[non_exhaustive]
    Early {
        /// The INVITE the response answered.
        attempt: AttemptId,
        /// The session of the early dialog.
        session: Session,
    },
    /// A 2xx confirmed a dialog. The ACK may still be owed, and the session
    /// descriptions may not be settled.
    #[non_exhaustive]
    Confirmed {
        /// The INVITE the 2xx answered, if this UA sent it.
        attempt: Option<AttemptId>,
        /// The session of the dialog.
        session: Session,
    },
    /// The offer/answer exchange of a session completed. The answer came,
    /// in the 2xx or the ACK, or the answer this UA owed in its ACK is fixed.
    /// The session's snapshot has what the peer sent. Whether that suits is
    /// for the application's SDP component to judge, since the UA does not
    /// read it.
    #[non_exhaustive]
    Negotiated {
        /// The session.
        session: Session,
    },
    /// The offer/answer exchange of a session failed, and the UA ends the
    /// session with a BYE, after the ACK, with
    /// [`EndReason::NegotiationFailed`]. The 2xx or the ACK lacked the answer
    /// or offer it owed (RFC 3261 section 13.2.1), or the [`Negotiate`] had no
    /// answer for the offer of a 2xx.
    #[non_exhaustive]
    NegotiationFailed {
        /// The session.
        session: Session,
    },
    /// The answer in a 2xx differs from the preview of it that a provisional
    /// response carried, which RFC 3261 section 13.2.1 does not allow. The
    /// preview stays the answer, as section 13.2.1 has the first session
    /// description be, and RFC 6337 section 3.1.1 keeps it even then. The
    /// session's snapshot has it. The peer is at fault, and the application
    /// may end the session.
    #[non_exhaustive]
    AnswerChanged {
        /// The session.
        session: Session,
    },
    /// No ACK came for the 2xx of an incoming INVITE within 64 T1 of the
    /// endpoint taking it, which is a little after its first transmission.
    /// The session ends next, with [`Event::Ended`] and
    /// [`EndReason::AckTimeout`]. If the application or a
    /// [`ShutdownMode::Terminate`] asked for its BYE while it waited for the
    /// ACK, that BYE goes now, and the session ends with
    /// [`EndReason::LocalBye`] or [`EndReason::Shutdown`] instead.
    ///
    /// It does not come for the 2xx of a re-INVITE once the peer sent a
    /// newer re-INVITE. The peer most likely lost the contact the 2xx went
    /// to, and the session goes on, as RFC 6141 section 5.4 recommends,
    /// unless that 2xx carried an offer whose answer the ACK owed.
    #[non_exhaustive]
    AckTimeout {
        /// The session.
        session: Session,
    },
    /// A session ended. Its snapshot keeps why for a while, see
    /// [`UaHandle::snapshot`].
    #[non_exhaustive]
    Ended {
        /// The session.
        session: Session,
        /// Why.
        reason: EndReason,
    },
    /// The caller gave up an INVITE the application had not decided, with a
    /// CANCEL or with a BYE in its early dialog, and the UA answered it with
    /// a 487 (RFC 3261 sections 9.2 and 15.1.2). So did a re-INVITE, with a
    /// CANCEL, or whose session ended by a BYE either way. The session of a
    /// re-INVITE cancelled so stays as it was. A decision the application
    /// submits now fails with [`Error::AlreadyFinalized`] or
    /// [`Error::StaleDecision`]. A final that was under way when the caller
    /// gave up goes on, and this does not come.
    #[non_exhaustive]
    Cancelled {
        /// The INVITE, as [`IncomingInvite::id`] said.
        invite: InviteId,
    },
    /// An INVITE this UA sent got no 2xx, which ended its early dialogs:
    /// its first final response was not a 2xx, or its transaction failed.
    #[non_exhaustive]
    Failed {
        /// The INVITE.
        attempt: AttemptId,
        /// Why, such as [`Error::RemoteFailure`] with the status of the
        /// final response, or [`Error::Timeout`].
        error: Error,
    },
    /// An INVITE this UA sent can get no more responses, and this is what it
    /// came to. It is the last event of the attempt, and it is never dropped
    /// for a full queue, since the UA set its place aside when it sent the
    /// INVITE.
    #[non_exhaustive]
    AttemptEnded {
        /// The INVITE.
        attempt: AttemptId,
        /// Whether a 2xx came.
        result: AttemptResult,
        /// Whether every response the endpoint took for the INVITE reached
        /// the UA and was kept. It is `false` when the endpoint drops
        /// responses for want of room, and a fork's 2xx may be among them,
        /// or when the UA could not keep a dialog as a session, such as a
        /// fork beyond [`Config::max_forks`] or a 2xx without a Contact.
        complete: bool,
        /// Whether the UA left a 2xx without its ACK and BYE, since it had
        /// no room even to end the dialog, beyond [`Config::max_cleanups`].
        /// The peer then gives up on the ACK, and ends the dialog itself.
        degraded: bool,
        /// The session of each dialog the responses formed that is still up,
        /// in the order they formed, as [`AttemptSnapshot::sessions`] listed
        /// them. The early ones no 2xx confirmed have ended by now. This event
        /// is never dropped, so a session whose [`Event::Confirmed`] was lost
        /// to a full queue is found here once the attempt's snapshot is gone.
        sessions: Vec<Session>,
    },
    /// Notifications were dropped because the queue was full.
    #[non_exhaustive]
    Lagged {
        /// How many.
        missed: u64,
    },
}

/// An INVITE, initial or a re-INVITE, and the authority to decide it.
///
/// The authority is this value, which cannot be cloned, so nothing can hand
/// the INVITE to a handler twice, as a retry middleware would. Submitting a
/// decision consumes it, and a refused submission hands it back. Dropping it
/// without a decision has the UA answer the INVITE with a 500, a policy of
/// this crate rather than an RFC rule. So does a decision that takes longer
/// than [`Config::decision_timeout`].
///
/// The INVITE may carry an offer, which [`IncomingInvite::offer`] returns.
/// Then the 2xx carries the answer. Without one, the 2xx carries an offer,
/// and the ACK owes the answer (RFC 3261 section 13.2.1). An INVITE whose body
/// may hold an offer the UA cannot take out, such as a multipart body, never
/// gets here. The UA answers it with a 415.
///
/// If the caller gives the INVITE up first, with a CANCEL or a BYE in its
/// early dialog, the UA answers it with a 487 and reports
/// [`Event::Cancelled`]. A final the application submitted before that goes
/// on and decides.
///
/// # Re-INVITE
///
/// A re-INVITE, from [`Event::Reinvite`], asks to change the session that
/// [`IncomingInvite::session`] names (RFC 3261 section 14.2). Deciding it
/// works as for an initial INVITE. A rejection, such as a 488 for an offer
/// the application does not take, leaves the session as it was, and so does
/// the UA's own 500 when the decision is dropped or late.
///
/// Prepare the answer without applying it, and apply it once
/// [`IncomingInvite::try_accept`] completes, when the endpoint has the 2xx.
/// Before that, the 2xx may lose to a CANCEL, and a session already changed
/// could not take the error response then (RFC 6141 section 3.3). With an
/// offer of the application's, for a re-INVITE without one, the answer comes
/// in the ACK, with [`Event::Negotiated`]. The 2xx commits the new remote
/// target of the re-INVITE's Contact, and an error response commits none
/// (RFC 6141 section 4.6).
///
/// The UA answers a re-INVITE that collides with another INVITE of the
/// dialog itself, without asking: a 491 if this UA's re-INVITE is pending,
/// and a 500 with a Retry-After if the peer's last one is undecided (RFC
/// 3261 section 14.2). It answers one with a 491 too while two 2xx of the
/// session wait for their ACK, so that a peer that never acknowledges cannot
/// have one session take the room of every other, which RFC 5407 section
/// 3.1.4 allows.
pub struct IncomingInvite {
    request: Request<Bytes>,
    /// The INVITE's share of [`Config::max_invite_bytes`], which goes back
    /// once neither this nor the UA keeps the INVITE.
    _bytes: Arc<OwnedSemaphorePermit>,
    flow: Flow,
    /// The session of a re-INVITE.
    session: Option<Session>,
    /// The offer and the preview are boxed, so that an INVITE without them
    /// makes [`Event`] no larger.
    offer: Option<Box<Description>>,
    /// The preview of the answer that a provisional response went out
    /// with, which the 2xx has to repeat.
    preview: Option<Box<Description>>,
    authority: Option<Authority>,
    /// A slot reserved in the driver's queue of abandoned INVITEs, so that
    /// dropping this always reaches the driver.
    abandon: Option<mpsc::OwnedPermit<ExchangeKey>>,
    shared: Arc<Shared>,
}

impl fmt::Debug for IncomingInvite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingInvite").finish_non_exhaustive()
    }
}

impl IncomingInvite {
    /// Returns the INVITE as received.
    pub fn request(&self) -> &Request<Bytes> {
        &self.request
    }

    /// Returns the session a re-INVITE is to change, or `None` for an
    /// initial INVITE.
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// Returns where the INVITE arrived: the transport, the local address
    /// it reached and the address it came from. It describes the flow, and
    /// sends nothing. An application that serves several networks on one
    /// endpoint can tell them apart by it.
    pub fn flow(&self) -> Flow {
        self.flow
    }

    /// Returns the offer the INVITE carries: its body, if that is a session
    /// description by its Content-Disposition, or by its Content-Type
    /// `application/sdp` without one (RFC 3261 section 20.11). The UA does
    /// not look inside it.
    pub fn offer(&self) -> Option<&Description> {
        self.offer.as_deref()
    }

    /// Returns the INVITE's identity, which [`Event::Cancelled`] names.
    pub fn id(&self) -> InviteId {
        let authority = self
            .authority
            .as_ref()
            .expect("a live invite holds its authority");
        InviteId { ua: self.shared.id, exchange: authority.exchange() }
    }

    /// Sends a provisional response, from 101 to 199, with the To tag every
    /// response to this INVITE carries. The endpoint sends the 100 itself.
    ///
    /// It decides nothing, so it keeps the authority. Until a final response
    /// is under way, the UA sends the last provisional that reached the
    /// endpoint again every minute, as RFC 3261 section 13.3.1.1 asks of a UAS
    /// that takes long to answer. The UA never picks a provisional of its
    /// own.
    ///
    /// The operation completes once the endpoint has the response. It fails
    /// with [`Error::AlreadyFinalized`] if a final response is under way or
    /// went first, and with [`Error::StaleDecision`] once the UA is done with
    /// the INVITE.
    ///
    /// # Errors
    ///
    /// Returns `status` with [`Error::InvalidInput`] for a status outside 101
    /// to 199, with [`Error::Busy`] when the command queue or the operations
    /// are full, or with [`Error::Closed`] once the driver has stopped.
    pub fn try_provisional(
        &self,
        status: StatusCode,
    ) -> Result<Operation<()>, SubmitError<StatusCode>> {
        if !(101..=199).contains(&status.as_u16()) {
            return Err(SubmitError {
                error: Error::InvalidInput,
                value: Box::new(status),
            });
        }

        let exchange = self
            .authority
            .as_ref()
            .expect("a live invite holds its authority")
            .exchange();
        self.shared.submit(status, |status| model::Command::Provisional {
            exchange,
            status,
            preview: None,
        })
    }

    /// Sends a provisional response, from 101 to 199, that carries `answer`,
    /// the answer to the INVITE's offer, ahead of the 2xx. It is a preview,
    /// as for early media, which RFC 3261 section 13.2.1 allows. The response
    /// is not reliable, so the 2xx has to carry the same answer, and
    /// [`IncomingInvite::try_accept`] refuses another one.
    ///
    /// Otherwise it is as [`IncomingInvite::try_provisional`]. The UA sends
    /// the preview again with the provisional response every minute.
    ///
    /// # Errors
    ///
    /// Returns `status` and `answer` with [`Error::InvalidInput`] for a status
    /// outside 101 to 199, an empty answer, an INVITE without an offer, whose
    /// 2xx has to carry an offer instead, or an answer other than one sent
    /// before, with [`Error::Busy`] when the command queue or the operations
    /// are full, or with [`Error::Closed`] once the driver has stopped.
    pub fn try_provisional_with(
        &mut self,
        status: StatusCode,
        answer: Description,
    ) -> Result<Operation<()>, SubmitError<(StatusCode, Description)>> {
        let valid = (101..=199).contains(&status.as_u16())
            && !answer.body().is_empty()
            && self.offer.is_some()
            && self
                .preview
                .as_deref()
                .is_none_or(|preview| *preview == answer);
        if !valid {
            return Err(SubmitError {
                error: Error::InvalidInput,
                value: Box::new((status, answer)),
            });
        }

        let exchange = self
            .authority
            .as_ref()
            .expect("a live invite holds its authority")
            .exchange();
        let operation = self.shared.submit(
            (status, answer.clone()),
            |(status, answer)| model::Command::Provisional {
                exchange,
                status,
                preview: Some(answer),
            },
        )?;
        self.preview = Some(Box::new(answer));
        Ok(operation)
    }

    /// Accepts the INVITE with a 200 that carries `answer`, the answer to its
    /// offer, or an offer of the application's when it had none.
    ///
    /// For a re-INVITE, the operation completes with the session it changed,
    /// which takes its next [`SessionSnapshot::session_revision`] with the
    /// answer, as the type documentation says.
    ///
    /// With an offer of its own, the session's exchange completes once the
    /// ACK brings the answer, with [`Event::Negotiated`], and the session's
    /// snapshot has that answer. An ACK without one fails the exchange, and
    /// the UA ends the session with a BYE, with
    /// [`Event::NegotiationFailed`].
    ///
    /// The 200 copies the INVITE's Record-Route and carries the UA's Contact.
    /// The UA sends it again until the ACK arrives, on every transport
    /// (RFC 3261 section 13.3.1.4). If none arrives within 64 T1, the UA
    /// reports [`Event::AckTimeout`] and ends the session, except as that
    /// event says for a re-INVITE.
    ///
    /// The operation completes once the endpoint has the 200, with the
    /// [`Session`] it established. That is neither the ACK nor delivery to
    /// the peer. It fails without sending the 200:
    ///
    /// * with [`Error::AlreadyFinalized`] if another final response is under
    ///   way, and [`Error::StaleDecision`] if the UA is already done with the
    ///   INVITE, as after a final at the decision timeout,
    /// * with [`Error::CapacityExceeded`] when the UA has no room for the
    ///   session, and the UA answers the INVITE with a 503,
    /// * with [`Error::CoreSubmissionRejected`] when the endpoint refuses the
    ///   200, and the UA answers the INVITE with a 500, since nobody holds
    ///   the decision any more.
    ///
    /// # Errors
    ///
    /// Returns this INVITE and `answer` with [`Error::InvalidInput`] when the
    /// body of `answer` is empty, or differs from the preview a provisional
    /// response carried, with [`Error::Busy`] when the command queue or the
    /// operations are full, or with [`Error::Closed`] once the driver has
    /// stopped.
    pub fn try_accept(
        self,
        answer: Description,
    ) -> Result<Operation<Session>, SubmitError<(IncomingInvite, Description)>>
    {
        let previewed =
            self.preview.as_deref().is_none_or(|preview| *preview == answer);
        if answer.body().is_empty() || !previewed {
            return Err(SubmitError {
                error: Error::InvalidInput,
                value: Box::new((self, answer)),
            });
        }

        let shared = self.shared.clone();
        shared.submit((self, answer), |(mut invite, answer)| {
            model::Command::Accept {
                authority: invite.take_authority(),
                answer,
            }
        })
    }

    /// Rejects the INVITE with `status`, which must be from 300 to 699.
    ///
    /// The response carries the To tag and what it copies from the INVITE,
    /// and nothing else. A status whose response needs a header of its own,
    /// such as the Allow of a 405, the challenge of a 401 or the Contact of a
    /// 3xx, cannot be sent as it should yet.
    ///
    /// # Errors
    ///
    /// Returns this INVITE with [`Error::InvalidInput`] for another status,
    /// with [`Error::Busy`] when the command queue or the operations are
    /// full, or with [`Error::Closed`] once the driver has stopped.
    pub fn try_reject(
        self,
        status: StatusCode,
    ) -> Result<Operation<()>, SubmitError<IncomingInvite>> {
        if !(300..=699).contains(&status.as_u16()) {
            return Err(SubmitError {
                error: Error::InvalidInput,
                value: Box::new(self),
            });
        }

        let shared = self.shared.clone();
        shared.submit(self, |mut invite| model::Command::Reject {
            authority: invite.take_authority(),
            status,
        })
    }

    fn take_authority(&mut self) -> Authority {
        // The reserved slot goes back unused, since a decision is coming.
        self.abandon = None;
        self.authority.take().expect("only a decision takes the authority")
    }
}

impl Drop for IncomingInvite {
    fn drop(&mut self) {
        if let (Some(authority), Some(abandon)) =
            (self.authority.take(), self.abandon.take())
        {
            abandon.send(authority.exchange());
        }
    }
}

/// A retry middleware cannot send an INVITE to its handler again. It replays
/// a request from a copy it made before the first call, and
/// [`IncomingInvite`] has no `Clone`, so a policy that copies its requests
/// does not apply. Nothing outside the crate can make one either, so a policy
/// written for it has no copy to give and retries nothing. What SIP asks to
/// send again stays with the UA: the copies of a 2xx until its ACK, and one
/// more re-INVITE after a 491.
///
/// ```compile_fail,E0277
/// use std::{convert::Infallible, future::{Ready, ready}};
///
/// use signa_ua::IncomingInvite;
/// use tower::{Service, retry::{Policy, Retry}, service_fn};
///
/// // Sends a request again after an error, from a copy of it.
/// #[derive(Clone)]
/// struct Again;
///
/// impl<Req: Clone, Res, E> Policy<Req, Res, E> for Again {
///     type Future = Ready<()>;
///
///     fn retry(
///         &mut self,
///         _: &mut Req,
///         result: &mut Result<Res, E>,
///     ) -> Option<Ready<()>> {
///         result.is_err().then(|| ready(()))
///     }
///
///     fn clone_request(&mut self, request: &Req) -> Option<Req> {
///         Some(request.clone())
///     }
/// }
///
/// fn serves_invites<S: Service<IncomingInvite>>(_: S) {}
///
/// let handler =
///     service_fn(|_: IncomingInvite| async { Ok::<(), Infallible>(()) });
/// serves_invites(Retry::new(Again, handler));
/// ```
#[cfg(doctest)]
fn middleware_cannot_retry_invite_implicitly() {}

/// Identifies an incoming INVITE, also among those of other UAs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InviteId {
    ua: UaId,
    exchange: ExchangeKey,
}

/// Identifies a session, also among those of other UAs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId {
    ua: UaId,
    usage: UsageKey,
}

/// An INVITE session, the INVITE usage of one dialog.
///
/// It is a handle. The UA keeps the session's state, and dropping this sends
/// no BYE. [`UaHandle::try_terminate`] does.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Session {
    id: SessionId,
}

impl Session {
    fn new(ua: UaId, usage: UsageKey) -> Session {
        Session { id: SessionId { ua, usage } }
    }

    /// Returns the session's identity.
    pub fn id(&self) -> SessionId {
        self.id
    }
}

/// Identifies an INVITE this UA sent, also among those of other UAs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AttemptId {
    ua: UaId,
    attempt: AttemptKey,
}

/// An initial INVITE this UA sent, which collects responses until the
/// endpoint stops delivering them.
///
/// Dropping it sends no CANCEL. The UA still acknowledges every 2xx.
/// [`UaHandle::try_cancel`] and [`UaHandle::try_abandon`] send one.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InviteAttempt {
    id: AttemptId,
}

impl InviteAttempt {
    /// Returns the attempt's identity.
    pub fn id(&self) -> AttemptId {
        self.id
    }
}

/// Where a session stands.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SessionSnapshot {
    /// The session's phase.
    pub phase: SessionPhase,
    /// The offer/answer exchange of its dialog.
    pub negotiation: NegotiationState,
    /// The last session description the peer sent: the offer of an INVITE
    /// this UA took, or the answer in its ACK, and for an INVITE this UA
    /// sent, the answer or offer in the 2xx. A preview of the answer that a
    /// provisional response gave stays the answer, as the first session
    /// description (RFC 3261 section 13.2.1). The UA does not check it. A
    /// session that ended no longer has it.
    pub remote_description: Option<Description>,
    /// Why the session ended, once it has.
    pub end_reason: Option<EndReason>,
    /// How many offer/answer exchanges of the session completed, the
    /// initial one and each re-INVITE's. It goes up when the session takes
    /// a new session description, and not before.
    pub session_revision: u32,
    /// How many times a target refresh replaced the peer's remote target
    /// since the dialog formed, as the 2xx of a re-INVITE does. It moves
    /// apart from the session revision (RFC 6141 section 4).
    pub target_revision: u32,
}

/// What an INVITE this UA sent has come to so far.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AttemptSnapshot {
    /// Whether a 2xx came, or why none did, once the first final response
    /// or a failure of the transaction is in.
    pub result: Option<AttemptResult>,
    /// Whether every response the endpoint took for the INVITE so far
    /// reached the UA and became part of a session, as
    /// [`Event::AttemptEnded`] says at the end.
    pub complete: bool,
    /// Whether the UA left a 2xx without its ACK and BYE so far, as
    /// [`Event::AttemptEnded`] says at the end.
    pub degraded: bool,
    /// The session of each dialog the responses formed that is still up,
    /// early or confirmed, in the order they formed. Forks are sessions of
    /// their own. None is preferred over another, and ending one ends no
    /// other.
    pub sessions: Vec<Session>,
}

/// The phase of a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SessionPhase {
    /// Its dialog is early.
    Early,
    /// A 2xx confirmed its dialog.
    Established,
    /// It is ending. Its BYE is on its way to the endpoint, or waits for
    /// the ACK of this UA's 2xx, or an early session waits for the CANCEL of
    /// its INVITE to take effect.
    Ending,
    /// It ended.
    Ended,
}

/// Where the offer/answer exchange of a session stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NegotiationState {
    /// No offer is outstanding.
    Settled,
    /// This UA made an offer and waits for the answer.
    AwaitingAnswer,
    /// The peer made an offer and waits for this UA's answer.
    AnswerOwed,
}

impl SessionSnapshot {
    fn new(state: UsageState) -> SessionSnapshot {
        let UsageState {
            phase,
            negotiation,
            remote,
            session_revision,
            target_revision,
            end_reason,
        } = state;
        SessionSnapshot {
            remote_description: remote,
            end_reason,
            session_revision,
            target_revision,
            phase: match phase {
                UsagePhase::Establishing => SessionPhase::Early,
                UsagePhase::Established => SessionPhase::Established,
                UsagePhase::Ending => SessionPhase::Ending,
                UsagePhase::Ended => SessionPhase::Ended,
            },
            negotiation: match negotiation {
                Negotiation::Stable => NegotiationState::Settled,
                Negotiation::LocalOfferOutstanding { .. } => {
                    NegotiationState::AwaitingAnswer
                }
                Negotiation::RemoteOfferOutstanding { .. } => {
                    NegotiationState::AnswerOwed
                }
            },
        }
    }
}

/// The future that runs a UA.
///
/// Spawn it, or poll it in a task of the application's. It returns once the
/// UA has stopped, after [`UaHandle::shutdown`] or once the endpoint stopped
/// on its own, and it has ended every task of the UA by then.
///
/// Dropping it stops the UA at once. This is a forced stop, not a graceful
/// shutdown. The endpoint's receiver goes with the driver, which shuts the
/// endpoint down. Every task of the UA is aborted, every [`Operation`] still
/// running fails with [`Error::DriverStopped`], and so does a [`UaShutdown`]
/// waiting for its report.
#[must_use = "the UA does nothing until its driver is polled"]
pub struct UaDriver {
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl fmt::Debug for UaDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UaDriver")
    }
}

impl Future for UaDriver {
    type Output = ();

    fn poll(mut self: Pin<&mut UaDriver>, cx: &mut Context<'_>) -> Poll<()> {
        self.future.as_mut().poll(cx)
    }
}
