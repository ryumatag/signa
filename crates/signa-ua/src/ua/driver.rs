/*!
The driver, the one task that changes UA state.

The driver owns the model, the endpoint's [`Incoming`], every server
transaction's [`Responder`] and every client transaction's [`ClientControl`].
None of them goes to the application, so nothing the application drops can
answer, cancel or abandon a transaction behind the UA's back.

Its loop waits on the endpoint's events, the handles' commands, abandoned
INVITEs, finished jobs, responses and the next deadline, and handles each one
without awaiting. Whatever has to wait, such as resolving a next hop or handing
a message to the endpoint, runs as a job on a [`JoinSet`], and its result comes
back to the loop as another input. A slow resolution therefore holds up only
its own request, and the loop keeps taking ACKs and CANCELs.

Every task belongs to one of two [`JoinSet`]s, so that dropping the driver
aborts all of them. Jobs are bounded by the configuration. More wait in a
backlog, which the model's own tables bound, since each job is for one of their
records. Response readers are one per attempt, which the attempt table bounds.
*/

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use signa_core::{
    Method, Request, Response, StatusCode,
    endpoint::{
        Branch, ClientControl, ClientTransaction, Endpoint,
        Error as CoreError, Incoming, IncomingEvent, Responder, ServerRequest,
        SubmitError, Target, ViaMode,
    },
    message::header::{CONTACT, RECORD_ROUTE, Tag},
};
use tokio::{
    sync::{OwnedSemaphorePermit, mpsc, oneshot},
    task::JoinSet,
    time::{Instant, sleep_until},
};

use super::{
    AttemptId, Command, Config, Event, IncomingInvite, Query, Resolve,
    ResolveError, Session, SessionSnapshot, Shared,
};
use crate::{
    error::Error,
    invite::{AttemptKey, ExchangeKey},
    model::{self, Effect, Model, Random, Released},
    operation::{Completion, OperationId},
    retention::ReplayKey,
    routing::initial_next_hop,
};

/// Randomness from the operating system, which RFC 3261 section 19.3 asks
/// of tags.
struct OsRandom;

impl Random for OsRandom {
    fn next_u64(&mut self) -> Option<u64> {
        getrandom::u64().ok()
    }
}

/// A response read from a client transaction, or `None` at its end.
type ResponseItem = Option<Result<Response<Bytes>, CoreError>>;

/// How many responses may wait between the readers and the driver. A reader
/// whose response does not fit waits, and the endpoint holds the rest under
/// its own limits.
const RESPONSE_QUEUE: usize = 64;

pub(super) struct Driver<R> {
    model: Model<OsRandom>,
    random: OsRandom,
    endpoint: Endpoint,
    incoming: Incoming,
    resolver: Arc<R>,
    contact: Box<str>,
    shared: Arc<Shared>,
    commands: mpsc::Receiver<Command>,
    abandon_sender: mpsc::Sender<ExchangeKey>,
    abandons: mpsc::Receiver<ExchangeKey>,
    events: mpsc::Sender<Event>,
    /// Notifications dropped since the last one that got through.
    lagged: u64,
    jobs: JoinSet<Done>,
    max_jobs: usize,
    resolve_timeout: Duration,
    backlog: VecDeque<Job>,
    readers: JoinSet<()>,
    response_sender: mpsc::Sender<(AttemptKey, ResponseItem)>,
    responses: mpsc::Receiver<(AttemptKey, ResponseItem)>,
    /// The INVITE and responder of each incoming exchange, until its final
    /// response is done with.
    servers: HashMap<ExchangeKey, Server>,
    /// The control of each attempt's client transaction, kept so that no
    /// handle the application drops can end it.
    clients: HashMap<AttemptKey, ClientControl>,
    /// Each ACK sent for a 2xx, to send again for a copy of that 2xx.
    acks: HashMap<ReplayKey, SentAck>,
    /// Who waits for each operation, and the permit it holds.
    waiters: HashMap<OperationId, Waiter>,
    /// The permits of outcomes kept after their waiter went away.
    kept: HashMap<OperationId, OwnedSemaphorePermit>,
}

struct Server {
    request: Request<Bytes>,
    responder: Arc<Responder>,
}

struct SentAck {
    request: Request<Bytes>,
    target: Target,
    /// The branch of the first ACK. Each copy goes out with it, so that the
    /// ACK of a 2xx keeps one identity (RFC 3261 section 13.2.2.4 has the
    /// UAC pass the same ACK to the transport again).
    branch: Branch,
}

struct Waiter {
    reply: oneshot::Sender<Result<Completion, Error>>,
    permit: OwnedSemaphorePermit,
}

/// Work that awaits, run as a task.
enum Job {
    /// Submit the final response of an incoming exchange.
    Final {
        exchange: ExchangeKey,
        responder: Arc<Responder>,
        response: Response<Bytes>,
    },
    /// Refuse a request before any exchange exists for it. Its result
    /// changes nothing.
    Refuse { responder: Arc<Responder>, response: Response<Bytes> },
    /// Resolve and send the INVITE of an attempt.
    Start { attempt: AttemptKey, request: Request<Bytes>, query: Query },
    /// Resolve and send the ACK of a 2xx, or send it again to where it went.
    Ack {
        replay: ReplayKey,
        request: Request<Bytes>,
        route: AckRoute,
        branch: Branch,
    },
}

enum AckRoute {
    Resolve(Query),
    Resend(Target),
}

/// What a finished job reports.
enum Done {
    Final { exchange: ExchangeKey, result: Result<(), SubmitError> },
    Nothing,
    Started { attempt: AttemptKey, result: Result<ClientTransaction, Error> },
    Acked { replay: ReplayKey, sent: Option<SentAck> },
}

impl<R: Resolve> Driver<R> {
    pub(super) fn new(
        endpoint: Endpoint,
        incoming: Incoming,
        config: Config<R>,
        shared: Arc<Shared>,
        commands: mpsc::Receiver<Command>,
        events: mpsc::Sender<Event>,
    ) -> Driver<R> {
        let (abandon_sender, abandons) = mpsc::channel(config.pending_invites);
        let (response_sender, responses) = mpsc::channel(RESPONSE_QUEUE);

        Driver {
            model: Model::new(config.limits(), OsRandom),
            random: OsRandom,
            endpoint,
            incoming,
            max_jobs: config.jobs,
            resolve_timeout: config.resolve_timeout,
            contact: config.contact,
            resolver: Arc::new(config.resolver),
            shared,
            commands,
            abandon_sender,
            abandons,
            events,
            lagged: 0,
            jobs: JoinSet::new(),
            backlog: VecDeque::new(),
            readers: JoinSet::new(),
            response_sender,
            responses,
            servers: HashMap::new(),
            clients: HashMap::new(),
            acks: HashMap::new(),
            waiters: HashMap::new(),
            kept: HashMap::new(),
        }
    }

    /// Runs the UA until the endpoint stops.
    ///
    /// TODO: Take a two-phase shutdown, which ends the UA's own work before
    /// it shuts the endpoint down. Until then the UA runs until the endpoint
    /// stops on its own.
    pub(super) async fn run(mut self) {
        loop {
            let deadline = self.model.next_deadline().map(Instant::from_std);

            tokio::select! {
                event = self.incoming.recv() => match event {
                    Some(event) => self.on_incoming(event),
                    None => break,
                },
                Some(command) = self.commands.recv() => {
                    self.on_command(command);
                }
                Some(exchange) = self.abandons.recv() => {
                    self.model.abandon(exchange, now());
                    self.settle(None);
                }
                Some(done) = self.jobs.join_next(), if !self.jobs.is_empty() => {
                    // A job that panicked reports nothing. Its record stays
                    // as it was, under the model's own limits.
                    if let Ok(done) = done {
                        self.on_done(done);
                    }
                }
                Some((attempt, item)) = self.responses.recv() => {
                    self.on_response(attempt, item);
                }
                Some(_) = self.readers.join_next(), if !self.readers.is_empty() => {}
                () = sleep_until(deadline.unwrap_or_else(Instant::now)),
                    if deadline.is_some() =>
                {
                    for operation in self.model.expire(now()) {
                        self.kept.remove(&operation);
                    }
                }
            }

            self.start_jobs();
        }
    }

    fn on_incoming(&mut self, event: IncomingEvent) {
        match event {
            IncomingEvent::Request(request)
                if *request.request.method() == Method::INVITE =>
            {
                self.on_invite(request);
            }
            IncomingEvent::Ack(ack) => {
                let answer = !ack.request.body().is_empty();
                self.model.receive_ack_request(&ack.request, answer);
                self.settle(None);
            }
            // TODO: Answer CANCEL with a 200 and its INVITE with a 487, and
            // take BYE and the other requests in a dialog. Until then each is
            // dropped, and dropping an unanswered responder has signa-core
            // send a 500.
            //
            // An unmatched CANCEL and a request without an RFC 3261 branch
            // get nothing. This UA keeps no state for either.
            _ => {}
        }
    }

    fn on_invite(&mut self, request: ServerRequest) {
        let ServerRequest { request, transaction, .. } = request;
        // TODO: Watch the server events for transport failures and the end
        // of the transaction.
        let (responder, _events) = transaction.into_parts();
        let responder = Arc::new(responder);

        // The decision needs a place in the event queue and a slot for its
        // abandonment, or the INVITE is refused before anything is kept for
        // it.
        let (Ok(slot), Ok(abandon)) = (
            self.events.try_reserve(),
            self.abandon_sender.clone().try_reserve_owned(),
        ) else {
            self.refuse(&request, responder, model::Refusal::Busy.status());
            return;
        };

        let offer = !request.body().is_empty();
        match self.model.receive_invite(&request, offer) {
            Ok(authority) => {
                let exchange = authority.exchange();
                self.servers.insert(
                    exchange,
                    Server { request: request.clone(), responder },
                );
                slot.send(Event::Invite(IncomingInvite {
                    request,
                    authority: Some(authority),
                    abandon: Some(abandon),
                    shared: self.shared.clone(),
                }));
            }
            Err(refusal) => {
                drop((slot, abandon));
                self.refuse(&request, responder, refusal.status());
            }
        }
        self.settle(None);
    }

    /// Answers a request the UA keeps nothing for. Each response but a 100
    /// carries a To tag (RFC 3261 section 8.2.6.2).
    fn refuse(
        &mut self,
        request: &Request<Bytes>,
        responder: Arc<Responder>,
        status: StatusCode,
    ) {
        let mut response = Response::reply_to(request).status(status);
        if let Some(tag) = self.tag() {
            response = response.to_tag(tag);
        }
        // A refusal belongs to no record of the model, so the model's tables
        // do not bound it. With the backlog full, or without a valid
        // response, dropping the responder has signa-core send its 500,
        // which costs the driver nothing more.
        if self.backlog.len() >= self.max_jobs {
            return;
        }
        if let Ok(response) = response.body(Bytes::new()) {
            self.backlog.push_back(Job::Refuse { responder, response });
        }
    }

    fn on_command(&mut self, command: Command) {
        match command {
            Command::Operation { command, reply, permit } => {
                match self.model.try_submit(command) {
                    Ok(operation) => {
                        self.waiters
                            .insert(operation, Waiter { reply, permit });
                        self.model.run_commands(now());
                    }
                    // The permit the handle took leaves room for every
                    // operation, so this does not happen.
                    Err(refused) => {
                        let _ = reply.send(Err(refused.error));
                    }
                }
            }
            Command::Snapshot { usage, reply } => {
                let snapshot = self.model.usage_state(usage).map(
                    |(phase, negotiation)| {
                        SessionSnapshot::new(phase, negotiation)
                    },
                );
                let _ = reply.send(snapshot);
            }
        }
        self.settle(None);
    }

    fn on_done(&mut self, done: Done) {
        let mut attempt = None;
        match done {
            Done::Final { exchange, result } => match result {
                Ok(()) => self.model.final_committed(exchange, now()),
                Err(error) => self.model.final_refused(
                    exchange,
                    error == SubmitError::Closed,
                    now(),
                ),
            },
            Done::Nothing => {}
            Done::Started { attempt: key, result } => {
                attempt = Some(key);
                match result {
                    Ok(transaction) => {
                        let (control, responses) = transaction.into_parts();
                        self.clients.insert(key, control);
                        self.read(key, responses);
                        self.model.invite_started(key, now());
                    }
                    Err(error) => self.model.invite_failed(key, error, now()),
                }
            }
            Done::Acked { replay, sent } => {
                self.model.ack_written(replay, sent.is_some());
                // The replay context may have been reclaimed while the job
                // ran. Its ACK is not kept then, or nothing would remove it.
                if let Some(sent) =
                    sent.filter(|_| self.model.has_replay(replay))
                {
                    self.acks.entry(replay).or_insert(sent);
                }
            }
        }
        self.settle(attempt);
    }

    /// Reads an attempt's responses in a task of their own, until the
    /// endpoint stops delivering them.
    fn read(
        &mut self,
        attempt: AttemptKey,
        mut responses: signa_core::endpoint::Responses,
    ) {
        let sender = self.response_sender.clone();
        self.readers.spawn(async move {
            while let Some(response) = responses.next().await {
                if sender.send((attempt, Some(response))).await.is_err() {
                    return;
                }
            }
            let _ = sender.send((attempt, None)).await;
        });
    }

    fn on_response(&mut self, attempt: AttemptKey, item: ResponseItem) {
        match item {
            Some(Ok(response)) => {
                let status = response.status();
                // An error here is a response that cannot form a dialog.
                // RFC 3261 leaves no way to answer it, so the UA keeps none.
                //
                // TODO: Report such a response, and send the ACK and a BYE
                // for a 2xx that cannot form a dialog.
                let _ = match status.as_u16() {
                    100..=199 => {
                        self.model.receive_provisional(attempt, &response)
                    }
                    200..=299 => self.model.receive_2xx(attempt, &response),
                    _ => {
                        self.model.receive_failure(attempt, status);
                        Ok(())
                    }
                };
            }
            // RFC 3261 section 8.1.3.1 treats a transaction timeout as a 408.
            Some(Err(error)) if error.is_timeout() => {
                let timeout = StatusCode::from_u16(408).expect("a status");
                self.model.receive_failure(attempt, timeout);
            }
            // TODO: Report a response overflow as an incomplete response
            // set, rather than leave the attempt to end quietly.
            Some(Err(_)) => {}
            None => {
                self.clients.remove(&attempt);
                self.model.response_collection_finished(attempt);
            }
        }
        self.settle(Some(attempt));
    }

    /// Carries out the model's effects until it has none left. `attempt` is
    /// the attempt the input that caused them was for, if any.
    fn settle(&mut self, attempt: Option<AttemptKey>) {
        loop {
            let effects = self.model.take_effects();
            if effects.is_empty() {
                return;
            }
            for effect in effects {
                self.apply(effect, attempt);
            }
        }
    }

    fn apply(&mut self, effect: Effect, attempt: Option<AttemptKey>) {
        match effect {
            Effect::SubmitFinal { exchange, status, to_tag } => {
                self.submit_final(exchange, status, to_tag);
            }
            Effect::StartInvite { attempt } => self.start_invite(attempt),
            Effect::SendAck { replay } => self.send_ack(replay),
            Effect::ResendAck { replay } => {
                // A copy that arrives before the first ACK is written finds
                // nothing to send. The peer retransmits the 2xx until it sees
                // an ACK, and a later copy gets one.
                if let Some(sent) = self.acks.get(&replay) {
                    self.backlog.push_back(Job::Ack {
                        replay,
                        request: sent.request.clone(),
                        route: AckRoute::Resend(sent.target),
                        branch: sent.branch.clone(),
                    });
                }
            }
            Effect::Notify(event) => self.notify(event, attempt),
            Effect::OperationEnded { operation } => self.deliver(operation),
            Effect::Released(Released::Exchange(exchange)) => {
                self.servers.remove(&exchange);
            }
            Effect::Released(Released::Replay(replay)) => {
                self.acks.remove(&replay);
            }
        }
    }

    fn submit_final(
        &mut self,
        exchange: ExchangeKey,
        status: StatusCode,
        to_tag: Tag,
    ) {
        let Some(server) = self.servers.get(&exchange) else {
            return;
        };

        let mut response =
            Response::reply_to(&server.request).status(status).to_tag(to_tag);
        if status.is_success() {
            // RFC 3261 section 12.1.1 has the UAS copy every Record-Route
            // value of the request into a response that forms a dialog, in
            // order, and add its Contact.
            for value in server.request.headers().get_all(RECORD_ROUTE) {
                response = response.header(RECORD_ROUTE, value.clone());
            }
            response = response
                .header(CONTACT, format!("<{}>", self.contact).as_str());
        }

        // TODO: Carry the answer to an offer in the 2xx, which the
        // application cannot supply yet.
        match response.body(Bytes::new()) {
            Ok(response) => self.backlog.push_back(Job::Final {
                exchange,
                responder: server.responder.clone(),
                response,
            }),
            Err(_) => self.model.final_refused(exchange, false, now()),
        }
    }

    fn start_invite(&mut self, attempt: AttemptKey) {
        let Some(request) = self.model.take_invite(attempt) else {
            return;
        };

        match initial_next_hop(request.uri().as_str(), request.headers()) {
            Ok((uri, false)) => {
                let query = Query { uri, size: request.to_bytes().len() };
                self.backlog.push_back(Job::Start { attempt, request, query });
            }
            // A secure hop needs TLS, which this UA does not have.
            Ok((_, true)) => {
                self.model.invite_failed(attempt, Error::Unroutable, now())
            }
            Err(_) => {
                self.model.invite_failed(attempt, Error::InvalidInput, now())
            }
        }
    }

    fn send_ack(&mut self, replay: ReplayKey) {
        let Some(outgoing) = self.model.ack_request(replay) else {
            return;
        };
        if outgoing.target.secure {
            self.model.ack_written(replay, false);
            return;
        }
        let Some(branch) = self.branch() else {
            self.model.ack_written(replay, false);
            return;
        };

        let request = outgoing.request.map(|()| Bytes::new());
        let query = Query {
            uri: outgoing.target.next_hop,
            size: request.to_bytes().len(),
        };
        self.backlog.push_back(Job::Ack {
            replay,
            request,
            route: AckRoute::Resolve(query),
            branch,
        });
    }

    /// Makes a fresh branch, with the magic cookie and 64 random bits.
    fn branch(&mut self) -> Option<Branch> {
        let branch = format!("z9hG4bK{:016x}", self.random.next_u64()?);
        Some(branch.parse().expect("a cookie and hexadecimal digits"))
    }

    /// Makes a To tag for a response the UA sends on its own.
    fn tag(&mut self) -> Option<Tag> {
        let tag = format!("{:016x}", self.random.next_u64()?);
        Some(tag.parse().expect("hexadecimal digits are a token"))
    }

    fn notify(&mut self, event: model::Event, attempt: Option<AttemptKey>) {
        let attempt = attempt.map(AttemptId);
        let event = match event {
            model::Event::EarlyDialog { usage, .. } => match attempt {
                Some(attempt) => {
                    Event::Early { attempt, session: Session::new(usage) }
                }
                None => return,
            },
            model::Event::DialogConfirmed { usage, .. } => {
                Event::Confirmed { attempt, session: Session::new(usage) }
            }
            model::Event::NegotiationCompleted { usage } => {
                Event::Negotiated { session: Session::new(usage) }
            }
            model::Event::UsageEnded { usage } => {
                Event::Ended { session: Session::new(usage) }
            }
            model::Event::AttemptFailed { attempt, status } => {
                Event::Failed { attempt: AttemptId(attempt), status }
            }
        };
        self.emit(event);
    }

    /// Queues a notification, or counts it as dropped when the queue is
    /// full. A count goes out as [`Event::Lagged`] before the next
    /// notification that fits.
    fn emit(&mut self, event: Event) {
        use mpsc::error::TrySendError;

        if self.lagged > 0 {
            match self.events.try_send(Event::Lagged { missed: self.lagged }) {
                Ok(()) => self.lagged = 0,
                Err(TrySendError::Full(_)) => {
                    self.lagged += 1;
                    return;
                }
                Err(TrySendError::Closed(_)) => return,
            }
        }

        if let Err(TrySendError::Full(_)) = self.events.try_send(event) {
            self.lagged += 1;
        }
    }

    /// Hands an outcome to its waiter. If the waiter is gone, the model
    /// keeps the outcome for a while, and the permit stays with it.
    fn deliver(&mut self, operation: OperationId) {
        let Some(waiter) = self.waiters.remove(&operation) else {
            return;
        };

        if waiter.reply.is_closed() {
            self.model.waiter_dropped(operation, now());
            self.kept.insert(operation, waiter.permit);
        } else if let Some(outcome) = self.model.take_outcome(operation) {
            let _ = waiter.reply.send(outcome);
        }
    }

    /// Spawns jobs from the backlog while there is room.
    fn start_jobs(&mut self) {
        while self.jobs.len() < self.max_jobs {
            let Some(job) = self.backlog.pop_front() else {
                return;
            };
            let endpoint = self.endpoint.clone();
            let resolver = self.resolver.clone();
            let timeout = self.resolve_timeout;
            self.jobs.spawn(job.run(endpoint, resolver, timeout));
        }
    }
}

impl Job {
    async fn run<R: Resolve>(
        self,
        endpoint: Endpoint,
        resolver: Arc<R>,
        timeout: Duration,
    ) -> Done {
        match self {
            Job::Final { exchange, responder, response } => {
                let result = responder.respond(response).await;
                Done::Final { exchange, result }
            }
            Job::Refuse { responder, response } => {
                let _ = responder.respond(response).await;
                Done::Nothing
            }
            Job::Start { attempt, request, query } => {
                let result = match resolve(&*resolver, &query, timeout).await {
                    Ok(target) => endpoint
                        .start(request, target)
                        .await
                        .map_err(core_error),
                    Err(_) => Err(Error::Unroutable),
                };
                Done::Started { attempt, result }
            }
            Job::Ack { replay, request, route, branch } => {
                let target = match route {
                    AckRoute::Resend(target) => Some(target),
                    AckRoute::Resolve(query) => {
                        resolve(&*resolver, &query, timeout).await.ok()
                    }
                };
                let Some(target) = target else {
                    return Done::Acked { replay, sent: None };
                };

                let via = ViaMode::Branch(branch.clone());
                let sent = endpoint
                    .send_request(request.clone(), target, via)
                    .await
                    .ok()
                    .map(|_| SentAck { request, target, branch });
                Done::Acked { replay, sent }
            }
        }
    }
}

/// Resolves a next hop, or gives up after `timeout`. A resolver that never
/// answers would otherwise hold a job slot for good, and with enough of them
/// no final response or ACK would get a slot either.
async fn resolve<R: Resolve>(
    resolver: &R,
    query: &Query,
    timeout: Duration,
) -> Result<Target, ResolveError> {
    tokio::time::timeout(timeout, resolver.resolve(query))
        .await
        .unwrap_or(Err(ResolveError::Unresolved))
}

/// Classifies a failure of the endpoint by what it says about the wire.
fn core_error(error: CoreError) -> Error {
    if error.is_closed() {
        Error::DriverStopped
    } else if error.is_transport() {
        Error::TransportFailure
    } else if error.is_busy() {
        Error::CoreSubmissionRejected
    } else {
        Error::InvalidInput
    }
}

fn now() -> std::time::Instant {
    Instant::now().into_std()
}
