/*!
The driver, the one task that changes UA state.

The driver owns the model, the endpoint's [`Incoming`], every server
transaction's [`Responder`] and every client transaction's [`ClientControl`].
None of them goes to the application, so nothing the application drops can
answer, cancel or abandon a transaction behind the UA's back.

Its loop waits on the endpoint's events, the handles' commands, abandoned
INVITEs, finished jobs, responses and the next deadline, which is the model's
next timer or outcome to reclaim, and handles each one without awaiting.
Whatever has to wait, such as resolving a next hop or handing a message to the
endpoint, runs as a job on a [`JoinSet`], and its result comes back to the loop
as another input. A slow resolution therefore holds up only its own request,
and the loop keeps taking ACKs and CANCELs.

Every task belongs to one of three [`JoinSet`]s, so that dropping the driver
aborts all of them. Jobs are bounded by the configuration. More wait in a
backlog, which the model's own tables bound, since each job is for one of their
records, and a record has at most one copy of its 2xx or its ACK on the way at
a time, and one BYE ever. A job that writes to the network gives up after a
while, so that a peer that does not read holds no job for long. Response
readers are one per attempt, which the attempt table bounds. Watchers wait on
the core for what can take long and writes nothing itself: the CANCEL of an
attempt, which waits for a provisional response (RFC 3261 section 9.1), one per
attempt at most, and the response to the BYE of a session, one per Mortal
dialog, which the dialog table bounds.
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
        Branch, CancelError, CancelOutcome, ClientControl, ClientTransaction,
        Endpoint, Error as CoreError, Incoming, IncomingCancel, IncomingEvent,
        ReceivedRequest, ReplyRoute, Responder, Responses, ServerRequest,
        ServerTransactionId, SubmitError, Target, ViaMode,
    },
    message::{
        header::{
            ALLOW, CONTACT, CONTENT_TYPE, RECORD_ROUTE, REQUIRE, Tag,
            UNSUPPORTED, WARNING,
        },
        response,
        uri::SipUri,
    },
};
use tokio::{
    sync::{OwnedSemaphorePermit, mpsc, oneshot},
    task::{self, JoinSet},
    time::{Instant, sleep_until},
};

use super::{
    AttemptId, AttemptSnapshot, Command, Config, Event, IncomingInvite,
    InviteId, Query, Resolve, ResolveError, Session, SessionSnapshot, Shared,
};
use crate::{
    error::Error,
    invite::{AttemptKey, CancelResult, ExchangeKey, UsageKey, UsagePhase},
    model::{
        self, ByeStarted, Effect, InDialog, Model, Random, Refusal, Released,
    },
    negotiation::Description,
    operation::{Completion, OperationId},
    plan::ALLOWED,
    protocol,
    retention::ReplayKey,
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

/// Room for the Via the endpoint adds to a request it sends, which the size
/// that picks the transport counts (RFC 3261 section 18.1.1). The endpoint
/// measures the request with its Via and refuses one over 1300 bytes for
/// UDP. Its Via is `SIP/2.0/UDP`, a `sent-by` of at most an IPv6 address
/// with a scope and a port, `;rport;branch=` and a branch, under 140 bytes
/// with its name and line end. Counting a little more moves a request near
/// the limit to TCP, which RFC 3261 allows of any request.
const VIA_ALLOWANCE: usize = 160;

pub(super) struct Driver<R> {
    model: Model<OsRandom>,
    random: OsRandom,
    endpoint: Endpoint,
    incoming: Incoming,
    resolver: Arc<R>,
    contact: Box<str>,
    /// The host and port of `contact`, which names the UA in a Warning
    /// (RFC 3261 section 20.43).
    agent: Box<str>,
    shared: Arc<Shared>,
    commands: mpsc::Receiver<Command>,
    abandon_sender: mpsc::Sender<ExchangeKey>,
    abandons: mpsc::Receiver<ExchangeKey>,
    events: mpsc::Sender<Event>,
    /// Notifications dropped since the last one that got through.
    lagged: u64,
    jobs: JoinSet<Done>,
    /// What each running job reports if it panics, such as in a resolver,
    /// so that the record it was for does not wait for it for good.
    fallbacks: HashMap<task::Id, Done>,
    max_jobs: usize,
    /// How many attempts may be live, each with a place in the event queue
    /// set aside for its last event.
    max_attempts: usize,
    resolve_timeout: Duration,
    /// How long a copy of a 2xx may wait for the endpoint, which is T2, the
    /// longest interval before the next copy is due anyway.
    resend_timeout: Duration,
    backlog: VecDeque<Job>,
    readers: JoinSet<()>,
    response_sender: mpsc::Sender<(AttemptKey, ResponseItem)>,
    responses: mpsc::Receiver<(AttemptKey, ResponseItem)>,
    /// The INVITE and responder of each incoming exchange, until its final
    /// response is done with.
    servers: HashMap<ExchangeKey, Server>,
    /// The exchange of each INVITE transaction in `servers`, which a CANCEL
    /// names by the transaction it matched.
    server_ids: HashMap<ServerTransactionId, ExchangeKey>,
    /// The control of each attempt's client transaction, kept so that no
    /// handle the application drops can end it. A watcher shares it while
    /// it waits for the CANCEL.
    clients: HashMap<AttemptKey, Arc<ClientControl>>,
    /// Waits on the core for a CANCEL to go and for the response to a BYE.
    watchers: JoinSet<Done>,
    /// The ACK of each 2xx, from when it is first built until its replay
    /// context goes, to send again for each copy of that 2xx.
    acks: HashMap<ReplayKey, Ack>,
    /// Who waits for each operation, and the permit it holds until its
    /// outcome.
    waiters: HashMap<OperationId, Waiter>,
    /// The place in the event queue set aside for the last event of each
    /// attempt, [`Event::AttemptEnded`].
    endings: HashMap<AttemptKey, mpsc::OwnedPermit<Event>>,
}

struct Server {
    request: Request<Bytes>,
    responder: Arc<Responder>,
    id: ServerTransactionId,
    /// The 2xx the core took, as it went out, to send again through the
    /// INVITE's reply route until the ACK.
    sent: Option<Response<Bytes>>,
    /// Whether a copy of the 2xx is on its way, so that copies do not pile up
    /// behind a busy endpoint.
    resending: bool,
}

struct Ack {
    request: Request<Bytes>,
    /// The branch of the first ACK. Each copy goes out with it, so that the
    /// ACK of a 2xx keeps one identity (RFC 3261 section 13.2.2.4 has the
    /// UAC pass the same ACK to the transport again).
    branch: Branch,
    /// The URI of the next hop, from the dialog as it was.
    next_hop: Box<str>,
    /// Where the ACK goes, once a resolution found it.
    target: Option<Target>,
    /// Whether a job is sending the ACK. A copy of the 2xx that arrives
    /// meanwhile is answered by that job, so that copies do not pile up
    /// behind a busy endpoint or a peer that does not read.
    sending: bool,
}

struct Waiter {
    reply: oneshot::Sender<Result<Completion, Error>>,
    /// The operation's place, which the handle took. It is held, not read,
    /// and dropping the waiter gives it back.
    _permit: OwnedSemaphorePermit,
}

/// Work that awaits, run as a task.
enum Job {
    /// Submit the final response of an incoming exchange.
    Final {
        exchange: ExchangeKey,
        responder: Arc<Responder>,
        response: Response<Bytes>,
    },
    /// Submit a provisional response of an incoming exchange.
    Provisional {
        exchange: ExchangeKey,
        operation: Option<OperationId>,
        responder: Arc<Responder>,
        response: Response<Bytes>,
    },
    /// Send a 2xx again, outside its transaction, waiting no longer than
    /// `timeout`.
    Resend {
        exchange: ExchangeKey,
        route: ReplyRoute,
        response: Response<Bytes>,
        timeout: Duration,
    },
    /// Refuse a request before any exchange exists for it. Its result
    /// changes nothing.
    Refuse { responder: Arc<Responder>, response: Response<Bytes> },
    /// Resolve and send the INVITE of an attempt.
    Start { attempt: AttemptKey, request: Request<Bytes>, query: Query },
    /// Resolve and send the BYE of a cleanup.
    Bye { replay: ReplayKey, request: Request<Bytes>, query: Query },
    /// Resolve and send the BYE that ends a session.
    SessionBye { usage: UsageKey, request: Request<Bytes>, query: Query },
    /// Answer a request that has no server transaction, through its route.
    /// Its result changes nothing.
    Reply { route: ReplyRoute, response: Response<Bytes> },
    /// Resolve and send the ACK of a 2xx, or send it again to where it went,
    /// waiting no longer than `timeout` for the write.
    Ack {
        replay: ReplayKey,
        request: Request<Bytes>,
        route: AckRoute,
        branch: Branch,
        timeout: Duration,
    },
}

enum AckRoute {
    Resolve(Query),
    Resend(Target),
}

/// What a finished job reports.
enum Done {
    /// `sent` is the response when it is a 2xx the core took.
    Final {
        exchange: ExchangeKey,
        result: Result<(), SubmitError>,
        sent: Option<Response<Bytes>>,
    },
    Provisional {
        exchange: ExchangeKey,
        operation: Option<OperationId>,
        status: StatusCode,
        result: Result<(), Error>,
    },
    Resent {
        exchange: ExchangeKey,
    },
    Nothing,
    Started {
        attempt: AttemptKey,
        result: Result<ClientTransaction, Error>,
    },
    /// The BYE of a cleanup went to the endpoint, or could not.
    Byed {
        replay: ReplayKey,
    },
    /// The BYE of a session went to the endpoint, or could not.
    SessionByeStarted {
        usage: UsageKey,
        result: Result<ClientTransaction, Error>,
    },
    /// The response to the BYE of a session, or why none came.
    ByeAnswered {
        bye: ByeStarted,
        result: Result<(), Error>,
    },
    /// What the endpoint did with a CANCEL it was asked for.
    Cancelled {
        operation: Option<OperationId>,
        result: Result<CancelResult, Error>,
    },
    /// `target` is where the ACK went, if it resolved, and `written`
    /// whether the endpoint wrote it in time.
    Acked {
        replay: ReplayKey,
        target: Option<Target>,
        written: bool,
    },
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
            model: Model::new(
                config.limits(),
                config.contact.clone(),
                OsRandom,
            ),
            random: OsRandom,
            endpoint,
            incoming,
            max_jobs: config.jobs,
            max_attempts: config.attempts,
            resolve_timeout: config.resolve_timeout,
            resend_timeout: config.timers.t2(),
            agent: warn_agent(&config.contact),
            contact: config.contact,
            resolver: Arc::new(config.resolver),
            shared,
            commands,
            abandon_sender,
            abandons,
            events,
            lagged: 0,
            jobs: JoinSet::new(),
            fallbacks: HashMap::new(),
            backlog: VecDeque::new(),
            readers: JoinSet::new(),
            response_sender,
            responses,
            servers: HashMap::new(),
            server_ids: HashMap::new(),
            clients: HashMap::new(),
            watchers: JoinSet::new(),
            acks: HashMap::new(),
            waiters: HashMap::new(),
            endings: HashMap::new(),
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
            let room = self.room();

            tokio::select! {
                event = self.incoming.recv() => match event {
                    Some(event) => self.on_incoming(event),
                    None => break,
                },
                Some(command) = self.commands.recv() => {
                    self.on_command(command);
                }
                Some(exchange) = self.abandons.recv() => {
                    self.model.abandon(exchange);
                    self.settle(None);
                }
                Some(done) = self.jobs.join_next_with_id(),
                    if !self.jobs.is_empty() =>
                {
                    self.on_joined(done);
                }
                Some(done) = self.watchers.join_next_with_id(),
                    if !self.watchers.is_empty() =>
                {
                    self.on_joined(done);
                }
                Some((attempt, item)) = self.responses.recv() => {
                    self.on_response(attempt, item);
                }
                Some(_) = self.readers.join_next(), if !self.readers.is_empty() => {}
                // Notifications were dropped, and the count waits for room,
                // so that the application learns of the loss even if nothing
                // else happens.
                () = report_lag(self.events.clone(), room, self.lagged),
                    if self.lagged > 0 && !self.events.is_closed() =>
                {
                    self.lagged = 0;
                }
                () = sleep_until(deadline.unwrap_or_else(Instant::now)),
                    if deadline.is_some() =>
                {
                    self.model.fire_timers(now());
                    self.settle(None);
                }
            }

            self.start_jobs();
        }
    }

    /// Takes what a job or watcher reported, or what it would have if it
    /// had not panicked.
    fn on_joined(
        &mut self,
        joined: Result<(task::Id, Done), task::JoinError>,
    ) {
        let done = match joined {
            Ok((id, done)) => {
                self.fallbacks.remove(&id);
                Some(done)
            }
            Err(error) => self.fallbacks.remove(&error.id()),
        };
        if let Some(done) = done {
            self.on_done(done);
        }
    }

    fn on_incoming(&mut self, event: IncomingEvent) {
        match event {
            IncomingEvent::Request(request)
                if *request.request.method() == Method::INVITE =>
            {
                self.on_invite(request);
            }
            IncomingEvent::Request(request) => self.on_other(request),
            IncomingEvent::Ack(ack) => {
                let answer = !ack.request.body().is_empty();
                self.model.receive_ack_request(&ack.request, answer);
                self.settle(None);
            }
            IncomingEvent::Cancel(cancel) => self.on_cancel(cancel),
            IncomingEvent::UnmatchedCancel(cancel) => {
                self.on_unmatched_cancel(cancel);
            }
            // A request without an RFC 3261 branch gets nothing. The core
            // keeps no transaction for it, and this UA no state.
            _ => {}
        }
    }

    /// Answers a CANCEL the core matched to a server transaction with a 200,
    /// whatever that transaction is (RFC 3261 section 9.2). For an INVITE
    /// the UA holds, the model decides what the CANCEL does to it, and the
    /// 200 carries the To tag of the INVITE's responses, as section 9.2
    /// recommends.
    ///
    /// CANCEL is not challenged, since it cannot be resubmitted (section
    /// 9.2), and a Require in it is ignored (section 8.2.2.3).
    ///
    /// The 200 needs a job, and the 487 the CANCEL may cause must not go
    /// without it, so a CANCEL that finds no room changes nothing. Its
    /// responder is dropped unanswered, and signa-core sends its 500. The
    /// peer then still has its INVITE pending, and may send the CANCEL again.
    fn on_cancel(&mut self, cancel: IncomingCancel) {
        let IncomingCancel { request, transaction, target, .. } = cancel;
        let (responder, _events) = transaction.into_parts();
        if !self.has_room() {
            return;
        }

        let tag = self
            .server_ids
            .get(&target)
            .copied()
            .and_then(|exchange| self.model.receive_cancel(exchange));
        let mut response = Response::reply_to(&request).status(StatusCode::OK);
        if let Some(tag) = tag {
            response = response.to_tag(tag);
        }
        self.answer_committed(Arc::new(responder), response);
        self.settle(None);
    }

    /// Answers a CANCEL that matches no transaction with a 481 (RFC 3261
    /// section 9.2). It has no transaction of its own, so the answer goes
    /// through its reply route, and a copy of it gets another.
    fn on_unmatched_cancel(&mut self, cancel: ReceivedRequest) {
        let ReceivedRequest { request, reply, .. } = cancel;
        let status = Refusal::NoDialog.status();
        let mut response = Response::reply_to(&request).status(status);
        if let Some(tag) = self.tag() {
            response = response.to_tag(tag);
        }

        // As in `answer_alone`, no table bounds such an answer, so it waits
        // for the backlog to have room, or does not go. The peer sends its
        // CANCEL again then.
        if !self.has_room() {
            return;
        }
        if let Ok(response) = response.body(Bytes::new()) {
            self.backlog.push_back(Job::Reply { route: reply, response });
        }
    }

    fn on_invite(&mut self, request: ServerRequest) {
        let ServerRequest { request, transaction, flow } = request;
        // TODO: Watch the server events, for a failed write of the first 2xx
        // and for the end of the transaction. The end would also bound how
        // long a merged INVITE is detected, which is now only while the UA
        // holds the exchange. Until then I drop them. Dropping them has no
        // protocol effect in signa-core, and the 2xx's retransmissions cover
        // a failed first write.
        let (responder, _events) = transaction.into_parts();
        let responder = Arc::new(responder);

        let offer =
            Description::from_message(request.headers(), request.body());
        let offered = offer.is_some();
        let authority = match self.model.receive_invite(&request, offer, now())
        {
            Ok(authority) => authority,
            Err(refusal) => {
                self.refuse(&request, responder, refusal);
                self.settle(None);
                return;
            }
        };
        let exchange = authority.exchange();
        let id = responder.id();
        self.server_ids.insert(id, exchange);
        self.servers.insert(
            exchange,
            Server {
                request: request.clone(),
                responder,
                id,
                sent: None,
                resending: false,
            },
        );

        // An INVITE without an offer would need an offer in the 2xx and the
        // answer checked in the ACK, which this UA cannot do yet. It is
        // answered with a 488 rather than let through to be accepted with
        // nothing to check the answer against. The status is my policy (RFC
        // 3261 section 21.4.26).
        if !offered {
            let not_acceptable = StatusCode::from_u16(488).expect("a status");
            self.model.reject(exchange, not_acceptable);
            self.settle(None);
            return;
        }

        // The decision needs a place in the event queue and a slot for its
        // abandonment. Without them, as when nobody reads the events, the UA
        // answers with the 503 of a server without room (RFC 3261 section
        // 21.5.4), which is my policy. The checks above come first, so that
        // an INVITE the UA refuses anyway gets its own status.
        let room = self.room();
        match (
            self.events.try_reserve_many(room),
            self.abandon_sender.clone().try_reserve_owned(),
        ) {
            (Ok(mut places), Ok(abandon)) => {
                let place = places.next().expect("room for one at least");
                place.send(Event::Invite(IncomingInvite {
                    request,
                    flow,
                    authority: Some(authority),
                    abandon: Some(abandon),
                    shared: self.shared.clone(),
                }));
            }
            _ => {
                let unavailable = StatusCode::from_u16(503).expect("a status");
                self.model.reject(exchange, unavailable);
            }
        }
        self.settle(None);
    }

    /// Answers a request other than INVITE, in the order of RFC 3261
    /// section 8.2, which section 12.2.2 applies to a request in a dialog
    /// too, before anything in the dialog changes:
    ///
    /// * The method (section 8.2.1). One of RFC 3261 or its extensions that
    ///   the UA does not take gets a 405 with the methods it takes, and one
    ///   it does not know a 501 (section 21.5.2).
    /// * Require (section 8.2.2.3). Any option tag gets a 420, since the UA
    ///   supports none.
    /// * The dialog. One with a To tag is in a dialog, and the model takes
    ///   it, checking its CSeq (section 12.2.2). A BYE it takes gets a 200
    ///   (section 15.1.2).
    ///
    /// Then a BYE outside a dialog gets a 481 (section 15.1.2), and OPTIONS a
    /// 200 with the methods the UA takes. Section 11.2 asks for the status an
    /// INVITE would get, which only the application knows. The 200 is my
    /// policy, so that a peer that checks whether the UA is up, as many
    /// trunks do, gets an answer.
    ///
    /// Each answer needs a job. A request that finds no room changes
    /// nothing, and its responder is dropped unanswered, so that signa-core
    /// sends its 500. A BYE the UA takes always gets its 200 (section 15.1.2
    /// makes it a MUST), since its room was there before the session ended.
    fn on_other(&mut self, request: ServerRequest) {
        let ServerRequest { request, transaction, flow } = request;
        let (responder, _events) = transaction.into_parts();
        let responder = Arc::new(responder);
        if !self.has_room() {
            return;
        }

        let method = request.method().clone();
        if method != Method::BYE && method != Method::OPTIONS {
            let (status, allow) = if KNOWN.contains(&method) {
                (405, true)
            } else {
                (501, false)
            };
            let status = StatusCode::from_u16(status).expect("a status");
            let mut response = Response::reply_to(&request).status(status);
            if allow {
                response = response.header(ALLOW, ALLOWED);
            }
            self.answer_alone(responder, response);
            return;
        }
        let headers = request.headers();
        let checked = protocol::to(headers).and_then(|to| {
            Ok((to.tag.is_some(), protocol::requires_extension(headers)?))
        });
        let in_dialog = match checked {
            Ok((_, true)) => {
                self.refuse(&request, responder, Refusal::BadExtension);
                return;
            }
            Ok((in_dialog, false)) => in_dialog,
            Err(malformed) => {
                self.refuse(&request, responder, malformed.into());
                return;
            }
        };

        if in_dialog {
            let taken = self.model.receive_request(&request, flow);
            self.settle(None);
            match taken {
                Ok(InDialog::Bye) => {
                    let ok =
                        Response::reply_to(&request).status(StatusCode::OK);
                    self.answer_committed(responder, ok);
                    return;
                }
                Ok(InDialog::Other) => {}
                Err(refusal) => {
                    self.refuse(&request, responder, refusal);
                    return;
                }
            }
        } else if method == Method::BYE {
            self.refuse(&request, responder, Refusal::NoDialog);
            return;
        }

        let response = Response::reply_to(&request)
            .status(StatusCode::OK)
            .header(ALLOW, ALLOWED);
        self.answer_committed(responder, response);
    }

    /// Answers a request the UA keeps nothing for, with the status of
    /// `refusal`.
    fn refuse(
        &mut self,
        request: &Request<Bytes>,
        responder: Arc<Responder>,
        refusal: Refusal,
    ) {
        let mut response =
            Response::reply_to(request).status(refusal.status());
        // A 420 lists the extensions the request requires that this UA does
        // not support, which are all of them (RFC 3261 section 8.2.2.3). The
        // model checked each row to be a list of option tags.
        if refusal == Refusal::BadExtension {
            for value in request.headers().get_all(REQUIRE) {
                response = response.header(UNSUPPORTED, value.clone());
            }
        }
        // RFC 5630 section 5.1.2 has a UAS that is not reached over SIPS say
        // so with the warning 380.
        if refusal == Refusal::SipsNotAllowed {
            let warning = format!("380 {} \"SIPS Not Allowed\"", self.agent);
            response = response.header(WARNING, warning.as_str());
        }
        self.answer_alone(responder, response);
    }

    /// Sends a response outside any record of the model, if the backlog has
    /// room. The model's tables do not bound such a response. With the
    /// backlog full, dropping the responder has signa-core send its 500,
    /// which costs the driver nothing more.
    fn answer_alone(
        &mut self,
        responder: Arc<Responder>,
        response: response::Builder,
    ) {
        if self.has_room() {
            self.answer_committed(responder, response);
        }
    }

    /// Sends a response whatever the backlog holds, since the request it
    /// answers already changed the UA's state. The caller checked
    /// [`Driver::has_room`] before that change, so one request adds one job
    /// at most beyond the limit.
    ///
    /// Each response but a 100 carries a To tag (RFC 3261 section 8.2.6.2).
    /// A request that had none gets a fresh one, and one in a dialog keeps
    /// its own. A response that cannot be built drops the responder, and
    /// signa-core sends its 500.
    fn answer_committed(
        &mut self,
        responder: Arc<Responder>,
        mut response: response::Builder,
    ) {
        if let Some(tag) = self.tag() {
            response = response.to_tag(tag);
        }
        if let Ok(response) = response.body(Bytes::new()) {
            self.backlog.push_back(Job::Refuse { responder, response });
        }
    }

    /// Says whether the backlog takes another job.
    fn has_room(&self) -> bool {
        self.backlog.len() < self.max_jobs
    }

    fn on_command(&mut self, command: Command) {
        match command {
            Command::Operation { command, reply, permit } => {
                match self.model.try_submit(command) {
                    Ok(operation) => {
                        self.waiters.insert(
                            operation,
                            Waiter { reply, _permit: permit },
                        );
                        self.model.run_commands();
                    }
                    // The permit the handle took leaves room for every
                    // operation, so this does not happen.
                    Err(refused) => {
                        let _ = reply.send(Err(refused.error));
                    }
                }
            }
            Command::Snapshot { usage, reply } => {
                let snapshot = match self.model.usage_state(usage) {
                    Some((phase, negotiation, remote)) => Some(
                        SessionSnapshot::new(phase, negotiation, remote, None),
                    ),
                    // A session that ended keeps why for a while, so that a
                    // lost notification does not leave the application
                    // guessing.
                    None => {
                        self.model.ended(usage).map(|(reason, negotiation)| {
                            SessionSnapshot::new(
                                UsagePhase::Ended,
                                negotiation,
                                None,
                                Some(reason),
                            )
                        })
                    }
                };
                let _ = reply.send(snapshot);
            }
            Command::AttemptSnapshot { attempt, reply } => {
                let ua = self.shared.id;
                let snapshot =
                    self.model.attempt_state(attempt).map(|state| {
                        AttemptSnapshot {
                            result: state.result,
                            complete: state.complete,
                            degraded: state.degraded,
                            sessions: state
                                .sessions
                                .into_iter()
                                .map(|usage| Session::new(ua, usage))
                                .collect(),
                        }
                    });
                let _ = reply.send(snapshot);
            }
        }
        self.settle(None);
    }

    fn on_done(&mut self, done: Done) {
        let mut attempt = None;
        match done {
            Done::Final { exchange, result, sent } => match result {
                Ok(()) => {
                    if let Some(server) = self.servers.get_mut(&exchange) {
                        server.sent = sent;
                    }
                    self.model.final_committed(exchange, now());
                }
                Err(error) => self
                    .model
                    .final_refused(exchange, error == SubmitError::Closed),
            },
            Done::Provisional { exchange, operation, status, result } => {
                self.model.provisional_done(
                    exchange,
                    status,
                    operation,
                    result,
                    now(),
                );
            }
            Done::Resent { exchange } => {
                if let Some(server) = self.servers.get_mut(&exchange) {
                    server.resending = false;
                }
            }
            Done::Nothing => {}
            Done::Started { attempt: key, result } => {
                attempt = Some(key);
                match result {
                    Ok(transaction) => {
                        let (control, responses) = transaction.into_parts();
                        self.clients.insert(key, Arc::new(control));
                        self.read(key, responses);
                        self.model.invite_started(key);
                    }
                    Err(error) => self.model.invite_failed(key, error),
                }
            }
            Done::Byed { replay } => self.model.bye_done(replay),
            Done::SessionByeStarted { usage, result } => {
                let (responses, result) = match result {
                    Ok(transaction) => {
                        let (_control, responses) = transaction.into_parts();
                        (Some(responses), Ok(()))
                    }
                    Err(error) => (None, Err(error)),
                };
                let started = self.model.bye_started(usage, result);
                if let (Some(bye), Some(responses)) = (started, responses) {
                    self.watch_bye(bye, responses);
                }
            }
            Done::ByeAnswered { bye, result } => {
                self.model.bye_answered(bye, result);
            }
            Done::Cancelled { operation, result } => {
                self.model.cancel_done(operation, result);
            }
            Done::Acked { replay, target, written } => {
                // The replay context and its ACK may have gone while the job
                // ran, and nothing is left to record then.
                if let Some(ack) = self.acks.get_mut(&replay) {
                    ack.sending = false;
                    ack.target = ack.target.or(target);
                }
                self.model.ack_written(replay, written);
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
                // An error here is a response the UA keeps no session for.
                // The model has queued what the wire still needs, such as
                // the ACK and BYE of a fork beyond the limits, and noted on
                // the attempt that its set of responses is not complete.
                let _ = match status.as_u16() {
                    100..=199 => {
                        self.model.receive_provisional(attempt, &response)
                    }
                    200..=299 => {
                        let description = Description::from_message(
                            response.headers(),
                            response.body(),
                        );
                        self.model.receive_2xx(attempt, &response, description)
                    }
                    _ => {
                        let error = Error::RemoteFailure(status);
                        self.model.attempt_failed(attempt, error);
                        Ok(())
                    }
                };
            }
            // The endpoint dropped responses for want of room. The
            // transaction goes on, but the UA sees no more of it.
            Some(Err(error)) if error.is_delivery_overflow() => {
                self.model.responses_lost(attempt);
            }
            // The transaction failed. A timeout counts as a 408 in RFC 3261
            // section 8.1.3.1, but no 408 came from the peer, so the UA
            // reports it as the timeout it is.
            Some(Err(error)) => {
                // After a CANCEL, the core stops waiting for a final 64 T1
                // later (RFC 3261 section 9.1), which is a timeout as well.
                let error = if error.is_timeout() || error.is_cancel_timeout()
                {
                    Error::Timeout
                } else if error.is_transport() {
                    Error::TransportFailure
                } else {
                    Error::DriverStopped
                };
                self.model.attempt_failed(attempt, error);
            }
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
            Effect::SubmitFinal { exchange, status, to_tag, body } => {
                self.submit_final(exchange, status, to_tag, body);
            }
            Effect::SubmitProvisional {
                exchange,
                status,
                to_tag,
                operation,
            } => {
                self.submit_provisional(exchange, status, to_tag, operation);
            }
            Effect::Resend2xx { exchange } => self.resend_2xx(exchange),
            Effect::StartInvite { attempt } => self.start_invite(attempt),
            Effect::SendAck { replay } => self.send_ack(replay),
            Effect::ResendAck { replay } => self.resend_ack(replay),
            Effect::SendBye { replay } => self.send_bye(replay),
            Effect::SendSessionBye { usage } => self.send_session_bye(usage),
            Effect::CancelInvite { attempt, operation } => {
                self.cancel_invite(attempt, operation);
            }
            Effect::Notify(event) => self.notify(event, attempt),
            Effect::OperationEnded { operation } => self.deliver(operation),
            Effect::AttemptEnded {
                attempt,
                result,
                complete,
                degraded,
                sessions,
            } => {
                let ua = self.shared.id;
                if let Some(permit) = self.endings.remove(&attempt) {
                    permit.send(Event::AttemptEnded {
                        attempt: AttemptId { ua, attempt },
                        result,
                        complete,
                        degraded,
                        sessions: sessions
                            .into_iter()
                            .map(|usage| Session::new(ua, usage))
                            .collect(),
                    });
                }
            }
            Effect::Released(Released::Attempt(attempt)) => {
                self.endings.remove(&attempt);
            }
            Effect::Released(Released::Exchange(exchange)) => {
                if let Some(server) = self.servers.remove(&exchange) {
                    self.server_ids.remove(&server.id);
                }
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
        body: Option<Description>,
    ) {
        let Some(server) = self.servers.get(&exchange) else {
            return;
        };

        // TODO: Let a rejection carry the headers its status needs, such as
        // the Allow of a 405 (RFC 3261 section 21.4.6) or the challenge of a
        // 401 (section 21.4.2).
        let mut response =
            Response::reply_to(&server.request).status(status).to_tag(to_tag);
        // A 2xx says which methods the UA takes (RFC 3261 section 13.3.1.4).
        if status.is_success() {
            response =
                dialog_headers(response, &server.request, &self.contact)
                    .header(ALLOW, ALLOWED);
        }
        let response = match body {
            Some(body) => response
                .header(CONTENT_TYPE, body.content_type().clone())
                .body(body.body().clone()),
            None => response.body(Bytes::new()),
        };

        match response {
            Ok(response) => self.backlog.push_back(Job::Final {
                exchange,
                responder: server.responder.clone(),
                response,
            }),
            Err(_) => self.model.final_refused(exchange, false),
        }
    }

    fn submit_provisional(
        &mut self,
        exchange: ExchangeKey,
        status: StatusCode,
        to_tag: Tag,
        operation: Option<OperationId>,
    ) {
        let Some(server) = self.servers.get(&exchange) else {
            return;
        };

        // A provisional response with a To tag forms an early dialog at the
        // UAC, so it carries what a 2xx does (RFC 3261 section 12.1.1).
        let response =
            Response::reply_to(&server.request).status(status).to_tag(to_tag);
        let response =
            dialog_headers(response, &server.request, &self.contact)
                .body(Bytes::new());

        match response {
            Ok(response) => self.backlog.push_back(Job::Provisional {
                exchange,
                operation,
                responder: server.responder.clone(),
                response,
            }),
            Err(_) => self.model.provisional_done(
                exchange,
                status,
                operation,
                Err(Error::InvalidInput),
                now(),
            ),
        }
    }

    /// Sends the 2xx of an exchange again, through the reply route rather
    /// than the responder. The transaction does not send a 2xx again itself
    /// (RFC 6026 section 7.1).
    fn resend_2xx(&mut self, exchange: ExchangeKey) {
        let Some(server) = self.servers.get_mut(&exchange) else {
            return;
        };
        let Some(response) = &server.sent else {
            return;
        };
        if server.resending {
            return;
        }

        server.resending = true;
        self.backlog.push_back(Job::Resend {
            exchange,
            route: server.responder.reply_route(),
            response: response.clone(),
            timeout: self.resend_timeout,
        });
    }

    fn start_invite(&mut self, attempt: AttemptKey) {
        use mpsc::error::TrySendError;

        let Some(planned) = self.model.take_invite(attempt) else {
            return;
        };
        // The last event of the attempt gets its place now, so that it is
        // never dropped. Other events leave a place for each attempt not yet
        // started, so one is free unless the application lets the events it
        // was sent pile up. Without a place the INVITE does not go out.
        // Without a receiver, nobody would read the event, so the INVITE goes
        // out without one.
        match self.events.clone().try_reserve_owned() {
            Ok(permit) => {
                self.endings.insert(attempt, permit);
            }
            Err(TrySendError::Full(_)) => {
                let error = Error::CapacityExceeded;
                self.model.invite_failed(attempt, error);
                return;
            }
            Err(TrySendError::Closed(_)) => {}
        }

        // A secure hop needs TLS, which this UA does not have.
        if planned.secure {
            self.model.invite_failed(attempt, Error::Unroutable);
            return;
        }
        let request = planned.request;
        let query = query(planned.next_hop, &request);
        self.backlog.push_back(Job::Start { attempt, request, query });
    }

    /// Builds the ACK of a 2xx from its dialog and sends it. The ACK is kept
    /// from now on, whether or not it gets out, so that each copy of the
    /// 2xx gets the same one, also after the dialog is gone.
    fn send_ack(&mut self, replay: ReplayKey) {
        // An ACK that cannot be built counts as one that did not get out, so
        // that a cleanup's BYE still follows it.
        let Some(outgoing) = self.model.ack_request(replay) else {
            self.model.ack_written(replay, false);
            return;
        };
        // A secure hop needs TLS, which this UA does not have.
        if outgoing.target.secure {
            self.model.ack_written(replay, false);
            return;
        }
        let Some(branch) = self.branch() else {
            self.model.ack_written(replay, false);
            return;
        };

        let request = outgoing.request.map(|()| Bytes::new());
        let next_hop = outgoing.target.next_hop;
        self.backlog.push_back(Job::Ack {
            replay,
            request: request.clone(),
            route: AckRoute::Resolve(query(next_hop.clone(), &request)),
            branch: branch.clone(),
            timeout: self.resend_timeout,
        });
        self.acks.insert(
            replay,
            Ack { request, branch, next_hop, target: None, sending: true },
        );
    }

    /// Sends the ACK of a 2xx again for a copy of the 2xx (RFC 3261 section
    /// 13.2.2.4), unless a job is already sending it. An ACK that never got
    /// out, or never resolved, gets another try here, so that one failure
    /// does not leave every later copy unanswered.
    fn resend_ack(&mut self, replay: ReplayKey) {
        let Some(ack) = self.acks.get_mut(&replay) else {
            // The first ACK could not even be built, as for a secure hop.
            // Building it again costs nothing on the wire.
            self.send_ack(replay);
            return;
        };
        if ack.sending {
            return;
        }

        let route = match ack.target {
            Some(target) => AckRoute::Resend(target),
            None => {
                AckRoute::Resolve(query(ack.next_hop.clone(), &ack.request))
            }
        };
        ack.sending = true;
        self.backlog.push_back(Job::Ack {
            replay,
            request: ack.request.clone(),
            route,
            branch: ack.branch.clone(),
            timeout: self.resend_timeout,
        });
    }

    /// Sends the BYE that ends the dialog of a 2xx the UA did not keep, once
    /// its ACK has had its first try (RFC 3261 section 13.2.2.4). It goes in
    /// a client transaction of its own (section 15.1.1), through the
    /// dialog's route set, as the ACK does.
    fn send_bye(&mut self, replay: ReplayKey) {
        let Some(outgoing) = self.model.bye_request(replay) else {
            self.model.bye_done(replay);
            return;
        };
        // A secure hop needs TLS, which this UA does not have.
        if outgoing.target.secure {
            self.model.bye_done(replay);
            return;
        }

        let request = outgoing.request.map(|()| Bytes::new());
        let query = query(outgoing.target.next_hop, &request);
        self.backlog.push_back(Job::Bye { replay, request, query });
    }

    /// Sends the BYE that ends a session, in a client transaction of its own
    /// (RFC 3261 section 15.1.1), through the dialog's route set.
    fn send_session_bye(&mut self, usage: UsageKey) {
        let outgoing = match self.model.session_bye_request(usage) {
            Ok(outgoing) => outgoing,
            Err(error) => {
                self.model.bye_started(usage, Err(error));
                return;
            }
        };
        // A secure hop needs TLS, which this UA does not have.
        if outgoing.target.secure {
            self.model.bye_started(usage, Err(Error::Unroutable));
            return;
        }

        let request = outgoing.request.map(|()| Bytes::new());
        let query = query(outgoing.target.next_hop, &request);
        self.backlog.push_back(Job::SessionBye { usage, request, query });
    }

    /// Reads the response to the BYE of a session, until its final or the
    /// end of its transaction, and reports it. A provisional changes
    /// nothing, and a non-2xx brings nothing back (RFC 3261 section 15.1.1).
    fn watch_bye(&mut self, bye: ByeStarted, mut responses: Responses) {
        let fallback = Done::ByeAnswered { bye, result: Err(Error::Internal) };
        let handle = self.watchers.spawn(async move {
            let result = loop {
                match responses.next().await {
                    Some(Ok(response)) if response.status().is_success() => {
                        break Ok(());
                    }
                    Some(Ok(response)) if response.status().is_final() => {
                        break Err(Error::RemoteFailure(response.status()));
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => break Err(transaction_error(&error)),
                    None => break Err(Error::DriverStopped),
                }
            };
            Done::ByeAnswered { bye, result }
        });
        self.fallbacks.insert(handle.id(), fallback);
    }

    /// Asks the endpoint to cancel the INVITE of an attempt, which it does
    /// once a provisional response came (RFC 3261 section 9.1). The wait can
    /// be long, so it runs as a watcher rather than a job.
    ///
    /// The CANCEL's own transaction is left to the endpoint. Its response
    /// says nothing about the INVITE, whose final is what counts (RFC 5407
    /// section 3.1.2), and a 481 to it ends nothing.
    fn cancel_invite(
        &mut self,
        attempt: AttemptKey,
        operation: Option<OperationId>,
    ) {
        // The responses ended, and the attempt with them, before the effect
        // ran. There is nothing left to cancel.
        let Some(control) = self.clients.get(&attempt).cloned() else {
            let not_needed = Ok(CancelResult::NotNeeded);
            self.model.cancel_done(operation, not_needed);
            return;
        };

        let fallback =
            Done::Cancelled { operation, result: Err(Error::Internal) };
        let handle = self.watchers.spawn(async move {
            let result = match control.cancel().await {
                Ok(CancelOutcome::Sent(_cancel)) => Ok(CancelResult::Sent),
                Ok(_) => Ok(CancelResult::NotNeeded),
                // The model asks once per attempt, so another request is
                // not the UA's.
                Err(
                    CancelError::AlreadyRequested | CancelError::NotInvite,
                ) => Err(Error::Internal),
                // Nothing was sent: no connection to the next hop could be
                // admitted, or opened.
                Err(CancelError::Busy) => Err(Error::CoreSubmissionRejected),
                Err(CancelError::Transport(_)) => Err(Error::TransportFailure),
                Err(_) => Err(Error::DriverStopped),
            };
            Done::Cancelled { operation, result }
        });
        self.fallbacks.insert(handle.id(), fallback);
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
        let ua = self.shared.id;
        let attempt = attempt.map(|attempt| AttemptId { ua, attempt });
        let event = match event {
            model::Event::EarlyDialog { usage, .. } => match attempt {
                Some(attempt) => {
                    Event::Early { attempt, session: Session::new(ua, usage) }
                }
                None => return,
            },
            model::Event::DialogConfirmed { usage, .. } => {
                Event::Confirmed { attempt, session: Session::new(ua, usage) }
            }
            model::Event::NegotiationCompleted { usage } => {
                Event::Negotiated { session: Session::new(ua, usage) }
            }
            model::Event::AckTimeout { usage } => {
                Event::AckTimeout { session: Session::new(ua, usage) }
            }
            model::Event::UsageEnded { usage, reason } => {
                Event::Ended { session: Session::new(ua, usage), reason }
            }
            model::Event::AttemptFailed { attempt, error } => {
                Event::Failed { attempt: AttemptId { ua, attempt }, error }
            }
            model::Event::InviteWithdrawn { exchange } => {
                Event::Cancelled { invite: InviteId { ua, exchange } }
            }
        };
        self.emit(event);
    }

    /// Queues a notification, or counts it as dropped when the queue is
    /// full. A count goes out as [`Event::Lagged`] before the next
    /// notification that fits.
    fn emit(&mut self, event: Event) {
        use mpsc::error::TrySendError;

        let room = self.room();
        if self.lagged > 0 {
            match self.events.try_reserve_many(room) {
                Ok(mut places) => {
                    let place = places.next().expect("room for one at least");
                    place.send(Event::Lagged { missed: self.lagged });
                    self.lagged = 0;
                }
                Err(TrySendError::Full(())) => {
                    self.lagged += 1;
                    return;
                }
                Err(TrySendError::Closed(())) => return,
            }
        }

        match self.events.try_reserve_many(room) {
            Ok(mut places) => {
                places.next().expect("room for one at least").send(event);
            }
            Err(TrySendError::Full(())) => self.lagged += 1,
            Err(TrySendError::Closed(())) => {}
        }
    }

    /// How many places in the event queue an event other than the end of an
    /// attempt needs free to take one: its own, and one for each attempt the
    /// UA may still start, whose last event must find a place
    /// ([`Driver::start_invite`]).
    fn room(&self) -> usize {
        let unstarted = self.max_attempts.saturating_sub(self.endings.len());
        unstarted.saturating_add(1).min(self.events.max_capacity())
    }

    /// Hands an outcome to its waiter, and lets go of the operation's permit.
    /// An outcome whose waiter is gone is dropped, since nothing else can
    /// read it.
    fn deliver(&mut self, operation: OperationId) {
        let Some(waiter) = self.waiters.remove(&operation) else {
            return;
        };

        if let Some(outcome) = self.model.take_outcome(operation) {
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
            let fallback = job.fallback();
            let handle = self.jobs.spawn(job.run(endpoint, resolver, timeout));
            self.fallbacks.insert(handle.id(), fallback);
        }
    }
}

impl Job {
    /// What the job reports if it panics. Nothing is known of its outcome
    /// then, so each record takes it as a failure that leaves nothing in
    /// flight:
    ///
    /// * A final response counts as one the endpoint may or may not have
    ///   taken, so nothing more goes out for it. Dropping its responder has
    ///   signa-core send its 500 if the final did not get out.
    /// * An INVITE that never started fails its attempt.
    /// * An ACK counts as not written, and the next copy of its 2xx tries
    ///   again.
    /// * A BYE counts as sent, since a BYE is never sent twice.
    fn fallback(&self) -> Done {
        match self {
            Job::Final { exchange, .. } => Done::Final {
                exchange: *exchange,
                result: Err(SubmitError::Closed),
                sent: None,
            },
            Job::Provisional { exchange, operation, response, .. } => {
                Done::Provisional {
                    exchange: *exchange,
                    operation: *operation,
                    status: response.status(),
                    result: Err(Error::Internal),
                }
            }
            Job::Resend { exchange, .. } => {
                Done::Resent { exchange: *exchange }
            }
            Job::Refuse { .. } => Done::Nothing,
            Job::Start { attempt, .. } => Done::Started {
                attempt: *attempt,
                result: Err(Error::Internal),
            },
            Job::Bye { replay, .. } => Done::Byed { replay: *replay },
            Job::SessionBye { usage, .. } => Done::SessionByeStarted {
                usage: *usage,
                result: Err(Error::Internal),
            },
            Job::Reply { .. } => Done::Nothing,
            Job::Ack { replay, route, .. } => Done::Acked {
                replay: *replay,
                target: match route {
                    AckRoute::Resend(target) => Some(*target),
                    AckRoute::Resolve(_) => None,
                },
                written: false,
            },
        }
    }

    async fn run<R: Resolve>(
        self,
        endpoint: Endpoint,
        resolver: Arc<R>,
        timeout: Duration,
    ) -> Done {
        match self {
            Job::Final { exchange, responder, response } => {
                // The 2xx is kept as it went out, so that each copy is the
                // same message (RFC 3261 section 13.3.1.4).
                let sent =
                    response.status().is_success().then(|| response.clone());
                let result = responder.respond(response).await;
                let sent = sent.filter(|_| result.is_ok());
                Done::Final { exchange, result, sent }
            }
            Job::Provisional { exchange, operation, responder, response } => {
                let status = response.status();
                // Each response is a job of its own, so a provisional can
                // reach the core after the final it was submitted before.
                // It lost to that final, as it would have in the model.
                let result =
                    responder.respond(response).await.map_err(|error| {
                        match error {
                            SubmitError::Closed => Error::DriverStopped,
                            SubmitError::FinalAlreadySent
                            | SubmitError::Terminated => {
                                Error::AlreadyFinalized
                            }
                            _ => Error::CoreSubmissionRejected,
                        }
                    });
                Done::Provisional { exchange, operation, status, result }
            }
            // A copy that does not get out changes nothing. The next one, or
            // the peer's ACK, settles it. A copy stuck behind a full endpoint
            // or a blocked connection is given up after `timeout`, so that it
            // holds no job slot for long and the next copy can take its
            // place. Giving up after the endpoint queued the copy withdraws
            // nothing, and giving up before costs nothing.
            Job::Resend { exchange, route, response, timeout } => {
                let _ =
                    tokio::time::timeout(timeout, route.send(response)).await;
                Done::Resent { exchange }
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
            // The UA keeps nothing of the BYE's transaction. Dropping it
            // leaves signa-core to retransmit the BYE and take its response,
            // which changes nothing here (RFC 3261 section 15.1.1). A BYE the
            // endpoint could not take is not tried again, so that a dialog
            // the UA never kept costs no more than this one try.
            Job::Bye { replay, request, query } => {
                if let Ok(target) = resolve(&*resolver, &query, timeout).await
                {
                    let _ = endpoint.start(request, target).await;
                }
                Done::Byed { replay }
            }
            // The core takes the BYE in a client transaction of its own, which
            // ends the session (RFC 3261 section 15.1.1). A BYE it could not
            // take is not tried again here. The model decides what that
            // means for the session.
            Job::SessionBye { usage, request, query } => {
                let result = match resolve(&*resolver, &query, timeout).await {
                    Ok(target) => endpoint
                        .start(request, target)
                        .await
                        .map_err(core_error),
                    Err(_) => Err(Error::Unroutable),
                };
                Done::SessionByeStarted { usage, result }
            }
            Job::Reply { route, response } => {
                let _ = route.send(response).await;
                Done::Nothing
            }
            // An ACK stuck behind a full endpoint or a peer that does not
            // read is given up after `timeout`, as a copy of a 2xx is, so
            // that it holds no job slot for long. It may still go out then,
            // which is no harm, since a copy of the ACK is what the next
            // copy of the 2xx gets anyway.
            Job::Ack { replay, request, route, branch, timeout: write } => {
                let target = match route {
                    AckRoute::Resend(target) => Some(target),
                    AckRoute::Resolve(query) => {
                        resolve(&*resolver, &query, timeout).await.ok()
                    }
                };
                let Some(target) = target else {
                    return Done::Acked {
                        replay,
                        target: None,
                        written: false,
                    };
                };

                let via = ViaMode::Branch(branch);
                let sent = tokio::time::timeout(
                    write,
                    endpoint.send_request(request, target, via),
                )
                .await;
                let written = matches!(sent, Ok(Ok(_)));
                Done::Acked { replay, target: Some(target), written }
            }
        }
    }
}

/// Adds what a response that forms a dialog carries: every Record-Route value
/// of the request, in order, and the UA's Contact (RFC 3261 section 12.1.1).
fn dialog_headers(
    mut response: response::Builder,
    request: &Request<Bytes>,
    contact: &str,
) -> response::Builder {
    for value in request.headers().get_all(RECORD_ROUTE) {
        response = response.header(RECORD_ROUTE, value.clone());
    }
    response.header(CONTACT, format!("<{contact}>").as_str())
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

/// Sends the count of dropped notifications once the event queue has
/// `room` places free, as [`Driver::room`] counts them.
async fn report_lag(events: mpsc::Sender<Event>, room: usize, missed: u64) {
    let Ok(mut places) = events.reserve_many(room).await else {
        return;
    };
    if let Some(place) = places.next() {
        place.send(Event::Lagged { missed });
    }
}

/// Methods of RFC 3261 and its extensions that the UA knows, and answers
/// with a 405 outside a dialog rather than a 501.
const KNOWN: [Method; 9] = [
    Method::REGISTER,
    Method::PRACK,
    Method::SUBSCRIBE,
    Method::NOTIFY,
    Method::PUBLISH,
    Method::INFO,
    Method::REFER,
    Method::MESSAGE,
    Method::UPDATE,
];

/// Returns the host and port of a Contact URI, as `warn-agent` takes them.
fn warn_agent(contact: &str) -> Box<str> {
    match SipUri::parse(contact) {
        Ok(uri) => match uri.port() {
            Some(port) => format!("{}:{port}", uri.host()).into(),
            None => uri.host().into(),
        },
        // `Config::new` checked the URI.
        Err(_) => "-".into(),
    }
}

/// Asks for the next hop of `request`, counting the Via the endpoint adds.
fn query(uri: Box<str>, request: &Request<Bytes>) -> Query {
    let size = request.to_bytes().len().saturating_add(VIA_ALLOWANCE);
    Query { uri, size }
}

/// Classifies a failure of the endpoint by what it says about the wire.
///
/// A UDP request too large for the endpoint is one a [`Resolve`] sent over
/// UDP against the size it was given, which the endpoint refused as it
/// refuses a busy one.
fn core_error(error: CoreError) -> Error {
    if error.is_closed() {
        Error::DriverStopped
    } else if error.is_transport() {
        Error::TransportFailure
    } else if error.is_busy() || error.is_too_large() {
        Error::CoreSubmissionRejected
    } else {
        Error::InvalidInput
    }
}

/// Classifies the failure of a client transaction, as its responses report
/// it.
fn transaction_error(error: &CoreError) -> Error {
    if error.is_timeout() || error.is_cancel_timeout() {
        Error::Timeout
    } else if error.is_transport() {
        Error::TransportFailure
    } else if error.is_delivery_overflow() {
        Error::ObservationIncomplete
    } else {
        Error::DriverStopped
    }
}

fn now() -> std::time::Instant {
    Instant::now().into_std()
}
