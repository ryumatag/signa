/*!
The UA's public handles, events and configuration. The driver that runs them
is in `driver`.
*/

use std::{
    error, fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use signa_core::{
    Request, StatusCode,
    endpoint::{Endpoint, Incoming, Reception, Target},
    transaction::Timers,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

pub use crate::{
    error::{Error, WireEffect},
    invite::AttemptResult,
    negotiation::Description,
    plan::InvitePlan,
    routing::{ResolveError, StaticResolver},
};
use crate::{
    invite::{AttemptKey, ExchangeKey, UsageKey, UsagePhase},
    model::{self, Authority, Limits},
    negotiation::Negotiation,
    operation::Completion,
    routing::{Place, allowed_in},
};

mod driver;

/// Resolves the next hop of a request to a transport and socket address.
///
/// The UA calls it for each request it sends outside a transaction's reply
/// path: an INVITE, and the ACK of each 2xx. Each call runs as a task of its
/// own, so a slow resolution holds up only its own request. The UA never asks
/// to resolve a hop that must be secured, since it has no TLS.
pub trait Resolve: Send + Sync + 'static {
    /// Resolves `query.uri()` for a request of `query.size()` bytes.
    fn resolve(
        &self,
        query: &Query,
    ) -> impl Future<Output = Result<Target, ResolveError>> + Send;
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
pub struct Config<R = StaticResolver> {
    contact: Box<str>,
    resolver: R,
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
        })
    }
}

impl<R> Config<R> {
    /// Resolves next hops with `resolver`.
    pub fn resolver<S: Resolve>(self, resolver: S) -> Config<S> {
        Config {
            contact: self.contact,
            resolver,
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
        }
    }

    /// Sets how many submitted operations may wait for the driver. A
    /// submission beyond it gets [`Error::Busy`]. The default is 256.
    pub fn command_capacity(mut self, capacity: usize) -> Config<R> {
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
    pub fn event_capacity(mut self, capacity: usize) -> Config<R> {
        self.events = bounded(capacity);
        self
    }

    /// Sets how many operations may run or keep an outcome at once. A
    /// submission beyond it gets [`Error::Busy`]. The default is 1024.
    pub fn max_operations(mut self, limit: usize) -> Config<R> {
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
    pub fn max_pending_invites(mut self, limit: usize) -> Config<R> {
        self.pending_invites = bounded(limit);
        self
    }

    /// Sets how many INVITEs this UA may have sent and still collect
    /// responses for. The default is 256.
    pub fn max_attempts(mut self, limit: usize) -> Config<R> {
        self.attempts = bounded(limit);
        self
    }

    /// Sets how many dialogs, early or confirmed, the UA keeps. The default
    /// is 1024.
    pub fn max_dialogs(mut self, limit: usize) -> Config<R> {
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
    pub fn max_forks(mut self, limit: usize) -> Config<R> {
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
    pub fn max_cleanups(mut self, limit: usize) -> Config<R> {
        self.cleanups = bounded(limit);
        self
    }

    /// Sets how many URIs a dialog's route set may have. A request or
    /// response with more cannot form a dialog. The default is 16.
    pub fn max_routes(mut self, limit: usize) -> Config<R> {
        self.routes = bounded(limit);
        self
    }

    /// Sets how many sends and resolutions may run at once. More wait their
    /// turn. The default is 256.
    pub fn max_jobs(mut self, limit: usize) -> Config<R> {
        self.jobs = bounded(limit);
        self
    }

    /// Sets how long a next hop may take to resolve. A resolution that
    /// takes longer counts as unresolved, so that a resolver that hangs holds
    /// no job for good. The default is 4 seconds.
    pub fn resolve_timeout(mut self, timeout: Duration) -> Config<R> {
        self.resolve_timeout = timeout;
        self
    }

    /// Sets T1 and T2, which pace the retransmission of each 2xx the UA sends
    /// and set the deadline for its ACK, 64 T1 later
    /// ([RFC 3261 section 13.3.1.4]). Give the endpoint's timers, so that the
    /// UA and the endpoint agree on them. The default is [`Timers::new`].
    ///
    /// [RFC 3261 section 13.3.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4
    pub fn timers(mut self, timers: Timers) -> Config<R> {
        self.timers = timers;
        self
    }

    /// Sets how long the application may take to decide an incoming INVITE.
    /// The UA answers an INVITE still undecided then with a 500, as one whose
    /// [`IncomingInvite`] was dropped. A timeout too long to add to the clock,
    /// such as [`Duration::MAX`], sets no deadline. The default is 3 minutes.
    pub fn decision_timeout(mut self, timeout: Duration) -> Config<R> {
        self.decision_timeout = timeout;
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
            // can arrive, so a dialog can leave one behind.
            replays: self.dialogs.saturating_mul(2),
            forks: self.forks,
            cleanups: self.cleanups,
            routes: self.routes,
            operations: self.operations,
            // The driver runs each command as it arrives.
            commands: 1,
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
/// Events arrive in order through a bounded queue. An [`IncomingInvite`] always
/// gets through, since the UA answers an INVITE it has no room to report with a
/// 503, as it does once [`UaEvents`] is dropped. A notification that does not
/// fit is dropped and counted, and the count comes as [`Event::Lagged`] as soon
/// as there is room, before any later notification. Nothing the protocol needs
/// is lost with it. The outcome of an operation comes through its
/// [`Operation`], and the state of a session through [`UaHandle::snapshot`].
///
/// # Dropping
///
/// Dropping a handle sends nothing. A [`Session`] or [`InviteAttempt`] going
/// away is neither a BYE nor a CANCEL, and the UA keeps answering and
/// acknowledging for it. The exception is an [`IncomingInvite`] dropped without
/// a decision. Nobody can answer it any more, so the UA does, with a 500.
///
/// # Errors
///
/// Returns [`AttachError::Stateless`] for an endpoint with stateless
/// reception.
pub fn attach<R: Resolve>(
    endpoint: Endpoint,
    incoming: Incoming,
    config: Config<R>,
) -> Result<Ua, AttachError> {
    if endpoint.reception() != Reception::Stateful {
        return Err(AttachError::Stateless);
    }

    let (commands, command_receiver) = mpsc::channel(config.commands);
    // The places of the attempts' last events come on top of the others.
    let capacity = bounded(config.events.saturating_add(config.attempts));
    let (events, event_receiver) = mpsc::channel(capacity);
    let shared = Arc::new(Shared {
        commands,
        operations: Arc::new(Semaphore::new(config.operations)),
    });
    let driver = driver::Driver::new(
        endpoint,
        incoming,
        config,
        shared.clone(),
        command_receiver,
        events,
    );

    Ok(Ua {
        handle: UaHandle { shared },
        events: UaEvents { receiver: event_receiver },
        driver: UaDriver { future: Box::pin(driver.run()) },
    })
}

/// What the handles share with the driver.
#[derive(Debug)]
struct Shared {
    commands: mpsc::Sender<Command>,
    /// One permit per operation that runs or keeps its outcome. A submission
    /// takes one, so that the driver always has room for what it admitted.
    operations: Arc<Semaphore>,
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
        Ok(Operation { receiver, kind: PhantomData })
    }
}

/// Submits operations to a UA.
#[derive(Clone, Debug)]
pub struct UaHandle {
    shared: Arc<Shared>,
}

impl UaHandle {
    /// Submits an initial INVITE, built from `plan` with the offer it
    /// carries.
    ///
    /// The UA picks the Call-ID, the From tag and the first CSeq number, adds
    /// its Contact, resolves the next hop from the first route or the
    /// Request-URI (RFC 3261 section 8.1.2), and hands the INVITE to the
    /// endpoint. The operation completes once the endpoint has it, with the
    /// [`InviteAttempt`] that collects its responses.
    ///
    /// Each dialog a response forms comes as an event, and the UA
    /// acknowledges each 2xx itself, whatever the application does with the
    /// session. No 2xx wins over another. The UA keeps each one as a session
    /// of its own. [`Event::AttemptEnded`] says what the INVITE came to once
    /// no more responses can arrive, and [`UaHandle::attempt_snapshot`] says
    /// it before.
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
    /// it, as [`InvitePlan`] says, with [`Error::Busy`] when the command
    /// queue or the operations are full, and with [`Error::Closed`] once the
    /// driver has stopped.
    pub fn try_invite(
        &self,
        plan: InvitePlan,
    ) -> Result<Operation<InviteAttempt>, SubmitError<InvitePlan>> {
        if !plan.is_valid() {
            return Err(SubmitError {
                error: Error::InvalidInput,
                value: Box::new(plan),
            });
        }

        self.shared.submit(plan, |plan| model::Command::Invite {
            plan: Box::new(plan),
        })
    }

    /// Returns what an INVITE this UA sent has come to so far, or `None` once
    /// it has ended and [`Event::AttemptEnded`] has said what it came to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] when the command queue is full,
    /// [`Error::Closed`] when the driver no longer takes commands, and
    /// [`Error::DriverStopped`] when it stopped before answering.
    pub async fn attempt_snapshot(
        &self,
        attempt: &InviteAttempt,
    ) -> Result<Option<AttemptSnapshot>, Error> {
        let slot =
            self.shared.commands.try_reserve().map_err(
                |error| match error {
                    mpsc::error::TrySendError::Full(()) => Error::Busy,
                    mpsc::error::TrySendError::Closed(()) => Error::Closed,
                },
            )?;
        let (reply, receiver) = oneshot::channel();
        slot.send(Command::AttemptSnapshot { attempt: attempt.id.0, reply });

        receiver.await.map_err(|_| Error::DriverStopped)
    }

    /// Returns where a session stands, or `None` once it has ended and the
    /// UA has let go of it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] when the command queue is full,
    /// [`Error::Closed`] when the driver no longer takes commands, and
    /// [`Error::DriverStopped`] when it stopped before answering.
    pub async fn snapshot(
        &self,
        session: &Session,
    ) -> Result<Option<SessionSnapshot>, Error> {
        let slot =
            self.shared.commands.try_reserve().map_err(
                |error| match error {
                    mpsc::error::TrySendError::Full(()) => Error::Busy,
                    mpsc::error::TrySendError::Closed(()) => Error::Closed,
                },
            )?;
        let (reply, receiver) = oneshot::channel();
        slot.send(Command::Snapshot { usage: session.id.0, reply });

        receiver.await.map_err(|_| Error::DriverStopped)
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
/// The operation goes on, and its outcome is kept for a while before the UA
/// lets go of it.
#[must_use = "an operation goes on without its future, but its outcome is lost"]
pub struct Operation<T> {
    receiver: oneshot::Receiver<Result<Completion, Error>>,
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
        self.poll_completion(cx).map(|outcome| match outcome? {
            Completion::Attempt(attempt) => {
                Ok(InviteAttempt { id: AttemptId(attempt) })
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
        self.poll_completion(cx).map(|outcome| match outcome? {
            Completion::Session(usage) => Ok(Session { id: SessionId(usage) }),
            _ => unreachable!("an accept completes with its session"),
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
    /// The offer/answer exchange of a session completed.
    #[non_exhaustive]
    Negotiated {
        /// The session.
        session: Session,
    },
    /// No ACK came for the 2xx of an incoming INVITE within 64 T1 of the
    /// endpoint taking it, which is a little after its first transmission.
    /// The session ends next, with [`Event::Ended`].
    #[non_exhaustive]
    AckTimeout {
        /// The session.
        session: Session,
    },
    /// A session ended.
    #[non_exhaustive]
    Ended {
        /// The session.
        session: Session,
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

/// An initial INVITE and the authority to decide it.
///
/// The authority is this value, which cannot be cloned. Submitting a
/// decision consumes it, and a refused submission hands it back. Dropping it
/// without a decision has the UA answer the INVITE with a 500, a policy of
/// this crate rather than an RFC rule. So does a decision that takes longer
/// than [`Config::decision_timeout`].
///
/// The INVITE carries an offer. The UA answers one without an offer itself,
/// with a 488, since its 2xx would have to carry an offer and its ACK the
/// answer, which this UA cannot check yet.
pub struct IncomingInvite {
    request: Request<Bytes>,
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
        })
    }

    /// Accepts the INVITE with a 200 that carries `answer`, the answer to its
    /// offer.
    ///
    /// The 200 copies the INVITE's Record-Route and carries the UA's Contact.
    /// The UA sends it again until the ACK arrives, on every transport
    /// (RFC 3261 section 13.3.1.4). If none arrives within 64 T1, the session
    /// ends with [`Event::AckTimeout`].
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
    /// body of `answer` is empty, with [`Error::Busy`] when the command queue
    /// or the operations are full, or with [`Error::Closed`] once the driver
    /// has stopped.
    pub fn try_accept(
        self,
        answer: Description,
    ) -> Result<Operation<Session>, SubmitError<(IncomingInvite, Description)>>
    {
        if answer.body().is_empty() {
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

/// Identifies a session within its UA.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId(UsageKey);

/// An INVITE session, the INVITE usage of one dialog.
///
/// It is a handle. The UA keeps the session's state, and dropping this sends
/// no BYE.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Session {
    id: SessionId,
}

impl Session {
    pub(crate) fn new(usage: UsageKey) -> Session {
        Session { id: SessionId(usage) }
    }

    /// Returns the session's identity.
    pub fn id(&self) -> SessionId {
        self.id
    }
}

/// Identifies an INVITE this UA sent.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AttemptId(AttemptKey);

/// An initial INVITE this UA sent, which collects responses until the
/// endpoint stops delivering them.
///
/// Dropping it sends no CANCEL. The UA still acknowledges every 2xx.
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
    /// this UA took, or the answer in the 2xx of one it sent. The UA does not
    /// check it.
    pub remote_description: Option<Description>,
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
    /// It is ending, with its BYE waiting for its turn.
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
    fn new(
        phase: UsagePhase,
        negotiation: Negotiation,
        remote_description: Option<Description>,
    ) -> SessionSnapshot {
        SessionSnapshot {
            remote_description,
            phase: match phase {
                UsagePhase::Establishing => SessionPhase::Early,
                UsagePhase::Established => SessionPhase::Established,
                UsagePhase::Ending => SessionPhase::Ending,
                UsagePhase::Ended => SessionPhase::Ended,
            },
            negotiation: match negotiation {
                Negotiation::Stable => NegotiationState::Settled,
                Negotiation::LocalOfferOutstanding => {
                    NegotiationState::AwaitingAnswer
                }
                Negotiation::RemoteOfferOutstanding => {
                    NegotiationState::AnswerOwed
                }
            },
        }
    }
}

/// The future that runs a UA.
///
/// Spawn it, or poll it in a task of the application's. It returns once the
/// endpoint has stopped.
///
/// Dropping it stops the UA at once. This is a forced stop, not a graceful
/// shutdown. The endpoint's receiver goes with the driver, which shuts the
/// endpoint down. Every task of the UA is aborted, and every [`Operation`]
/// still running fails with [`Error::DriverStopped`].
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
