/*!
Owned server transaction-user operations.

The driver accepts responses according to RFC 3261 sections 17.2.1 and 17.2.2,
RFC 6026 section 8.7 and RFC 4320 section 4. Local acceptance is distinct from
transport completion and transaction termination.
*/

use std::{
    error, fmt,
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, watch};

use super::{driver::Command, reply::ReplyRoute, table::Id};
use crate::{
    message::{Method, Request, Response},
    transport::{
        budget::{Budget, Permit},
        Flow,
    },
};

/// Receives owned incoming events from one endpoint.
///
/// `recv` is cancellation-safe. Taking an event does not release its place in
/// [`Builder::max_pending_requests`]. That lasts until the request has a final
/// response or its transaction ends. Events left unread do not hold a graceful
/// shutdown, although a request event's transaction does until it ends.
///
/// Dropping this receiver starts an immediate shutdown, as
/// [`Endpoint::shutdown`] with a zero deadline does, because no transaction
/// user is left to receive requests. Keep it for as long as the endpoint runs,
/// including in an application that only sends requests. Such an application
/// still receives requests on its sockets, such as a BYE within a dialog, and
/// should answer or reject them.
///
/// [`Builder::max_pending_requests`]: super::Builder::max_pending_requests
/// [`Endpoint::shutdown`]: super::Endpoint::shutdown
#[derive(Debug)]
pub struct Incoming {
    pub(super) receiver: mpsc::UnboundedReceiver<Queued>,
    shutdown: Arc<super::shutdown::Control>,
    control: mpsc::Sender<()>,
}

impl Drop for Incoming {
    fn drop(&mut self) {
        // The same coalesced request as `Endpoint::shutdown(Duration::ZERO)`.
        // A full control queue already holds a pending wakeup, which reads
        // the earliest deadline.
        if self.shutdown.request(std::time::Duration::ZERO) {
            let _ = self.control.try_send(());
        }
    }
}

impl Incoming {
    pub(super) fn new(
        receiver: mpsc::UnboundedReceiver<Queued>,
        shutdown: Arc<super::shutdown::Control>,
        control: mpsc::Sender<()>,
    ) -> Incoming {
        Incoming { receiver, shutdown, control }
    }

    /// Receives the next event, or `None` once the endpoint has stopped and
    /// every queued event has been received.
    pub async fn recv(&mut self) -> Option<IncomingEvent> {
        self.receiver.recv().await.map(|queued| queued.event)
    }
}

/// Queue ownership is separate from transaction work. A terminated transaction
/// cannot return the bytes of an event that the application has not received.
#[derive(Debug)]
pub(super) struct Queued {
    pub(super) event: IncomingEvent,
    pub(super) _permit: Permit,
}

/// A message delivered by an endpoint.
///
/// A [`Reception::Stateful`] endpoint delivers the first five, see the
/// [module docs](super#reception) for which event each request becomes. A
/// [`Reception::Stateless`] endpoint delivers only the last two.
///
/// # Example
///
/// The receive loop of a small stateful UAS. Ordinary requests go to tasks of
/// their own, so a slow handler does not hold up the loop, which ACK and
/// CANCEL also come through. The enum is non-exhaustive, so the loop ends with
/// a `_` arm.
///
/// ```
/// use bytes::Bytes;
/// use signa::{
///     endpoint::{Incoming, IncomingCancel, IncomingEvent, ReceivedAck},
///     message::header::Tag,
///     Method, Response,
/// };
///
/// // The UAS core's CANCEL and ACK handling, which needs its dialogs.
/// async fn cancel_call(_cancel: IncomingCancel) {}
/// async fn dispatch_ack(_ack: ReceivedAck) {}
///
/// async fn serve(mut incoming: Incoming) {
///     while let Some(event) = incoming.recv().await {
///         match event {
///             IncomingEvent::Request(envelope) => {
///                 tokio::spawn(async move {
///                     let (responder, _events) =
///                         envelope.transaction.into_parts();
///                     let status = match *envelope.request.method() {
///                         Method::INVITE => 486,
///                         _ => 200,
///                     };
///                     let response = Response::reply_to(&envelope.request)
///                         .status(status)
///                         .to_tag(Tag::random())
///                         .body(Bytes::new());
///                     if let Ok(response) = response {
///                         let _ = responder.respond(response).await;
///                     }
///                 });
///             }
///             // The TU answers the CANCEL with a 200 and, if the request
///             // named by `cancel.target` is an INVITE without a final
///             // response yet, that INVITE with a 487.
///             IncomingEvent::Cancel(cancel) => cancel_call(cancel).await,
///             // An ACK for a 2xx, which the TU matches to its dialog by
///             // Call-ID, tags and CSeq.
///             IncomingEvent::Ack(ack) => dispatch_ack(ack).await,
///             // Nothing to cancel. A UAS answers 481 through the route.
///             IncomingEvent::UnmatchedCancel(cancel) => {
///                 let response = Response::reply_to(&cancel.request)
///                     .status(481)
///                     .to_tag(Tag::random())
///                     .body(Bytes::new());
///                 if let Ok(response) = response {
///                     let _ = cancel.reply.send(response).await;
///                 }
///             }
///             // No transaction can be kept for it. Dropping it sends
///             // nothing.
///             IncomingEvent::Untracked(_) => {}
///             _ => {}
///         }
///     }
/// }
/// ```
///
/// [`Reception::Stateful`]: super::Reception::Stateful
/// [`Reception::Stateless`]: super::Reception::Stateless
#[derive(Debug)]
#[non_exhaustive]
pub enum IncomingEvent {
    /// A new INVITE or non-INVITE server transaction, other than CANCEL.
    Request(ServerRequest),
    /// A CANCEL that matches a server transaction, with its own transaction.
    Cancel(IncomingCancel),
    /// An ACK that no transaction absorbed: one for a 2xx, which matches an
    /// INVITE in Accepted, or one that matches nothing.
    Ack(ReceivedAck),
    /// A CANCEL that matches no server transaction. It gets no transaction
    /// and no automatic response, and its retransmissions arrive as new
    /// events.
    UnmatchedCancel(ReceivedRequest),
    /// A request without an RFC 3261 branch, which gets no transaction. Its
    /// retransmissions arrive as new events.
    Untracked(ReceivedRequest),
    /// A request received by a stateless endpoint, of any method.
    ///
    /// No transaction exists for it, so each retransmission is a new event,
    /// and nothing answers it unless the TU does through its reply route. The
    /// route of an ACK refuses every response.
    StatelessRequest(ReceivedRequest),
    /// A response received by a stateless endpoint, whether or not it sent
    /// the request. Its Via is as it arrived, with this endpoint's value still
    /// on top. See [`Endpoint::forward_response`] for what a proxy does next.
    ///
    /// [`Endpoint::forward_response`]: super::Endpoint::forward_response
    StatelessResponse(ReceivedResponse),
}

/// An owned request with its response and observation capabilities.
#[derive(Debug)]
pub struct ServerRequest {
    /// The received request, with `received` and `rport` filled in its top
    /// Via.
    pub request: Request<Bytes>,
    /// Descriptive metadata for the original received flow.
    pub flow: Flow,
    /// Response submission and independent transaction observation.
    pub transaction: ServerTransaction,
}

/// A CANCEL and the server transaction it targets.
///
/// [RFC 3261 section 9.2] matches a CANCEL by the branch and `sent-by` of the
/// target's top Via, whatever the target's method. signa does not act on the
/// target. A UAS answers the CANCEL with a 200 and its INVITE with a 487 if it
/// has not sent a final response yet. A proxy cancels its pending branches. A
/// CANCEL of a non-INVITE request has no effect on that request.
///
/// The CANCEL's own transaction answers its retransmissions, even after the
/// target has ended. Dropping its responder sends a 500 as for any request.
///
/// [RFC 3261 section 9.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9.2
#[derive(Debug)]
pub struct IncomingCancel {
    /// The received CANCEL, with `received` and `rport` filled in its top
    /// Via.
    pub request: Request<Bytes>,
    /// Descriptive metadata for the original received flow.
    pub flow: Flow,
    /// The CANCEL's own non-INVITE server transaction.
    pub transaction: ServerTransaction,
    /// The transaction the CANCEL targets, as its [`Responder::id`] says.
    pub target: ServerTransactionId,
}

/// An ACK for the transaction user.
///
/// An ACK for a 2xx is a request of its own, which the UAC core sends
/// ([RFC 3261 section 13.2.2.4]) and the UAS core matches to its dialog. It
/// has no reply capability, since no response to an ACK exists. The TU
/// stops its 2xx retransmissions when it gets the ACK
/// ([RFC 3261 section 13.3.1.4], [RFC 6026 section 8.1]).
///
/// [RFC 3261 section 13.2.2.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4
/// [RFC 3261 section 13.3.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4
/// [RFC 6026 section 8.1]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.1
#[derive(Debug)]
pub struct ReceivedAck {
    /// The received ACK, with `received` and `rport` filled in its top Via.
    pub request: Request<Bytes>,
    /// Descriptive metadata for the original received flow.
    pub flow: Flow,
}

/// An owned request without a server transaction: one that could not be
/// tracked, an unmatched CANCEL, or any request on a stateless endpoint.
///
/// Dropping it sends nothing.
#[derive(Debug)]
pub struct ReceivedRequest {
    /// The received request, with `received` and `rport` filled in its top
    /// Via.
    pub request: Request<Bytes>,
    /// Descriptive metadata for the original received flow.
    pub flow: Flow,
    /// One-shot reply capability retaining the received route.
    pub reply: ReplyRoute,
}

/// An owned response received by a stateless endpoint.
///
/// It has no reply capability. Forwarding it is
/// [`Endpoint::forward_response`], once the TU has checked and removed its own
/// Via value. Dropping it sends nothing.
///
/// [`Endpoint::forward_response`]: super::Endpoint::forward_response
#[derive(Debug)]
pub struct ReceivedResponse {
    /// The received response, as it arrived.
    pub response: Response<Bytes>,
    /// Descriptive metadata for the flow it arrived on.
    pub flow: Flow,
}

/// Identifies a server transaction within this process.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ServerTransactionId(pub(super) u64);

/// Identifies a response submission, including its transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResponseId {
    transaction: ServerTransactionId,
    sequence: u64,
}

impl ResponseId {
    /// Returns the transaction that owns this response submission.
    pub fn transaction(&self) -> ServerTransactionId {
        self.transaction
    }
}

/// Owns the responder and the independent event observer.
#[derive(Debug)]
pub struct ServerTransaction {
    pub(super) responder: Responder,
    pub(super) events: ServerEvents,
}

impl ServerTransaction {
    /// Returns the identity of this server transaction.
    pub fn id(&self) -> ServerTransactionId {
        self.responder.id()
    }

    /// Separates response submission from transaction observation.
    pub fn into_parts(self) -> (Responder, ServerEvents) {
        (self.responder, self.events)
    }
}

/// An owned, non-cloneable right to submit responses.
///
/// Dropping it before a final response is accepted sends a 500, as described
/// in the [module docs](super). The 500 waits for submissions already
/// enqueued, even if their futures were dropped. If the 500 cannot be
/// admitted, the transaction ends. Dropping it after a final response has no
/// protocol effect. That includes an INVITE in Accepted. Its 2xx
/// retransmissions are the TU's, through [`Responder::reply_route`], over TCP
/// as well as UDP, since the 2xx is retransmitted end to end and a later hop
/// may be UDP ([RFC 3261 section 13.3.1.4]).
///
/// A stateful proxy forwards every response through its responder, which
/// refuses what its transaction no longer allows, such as anything after
/// Timer L ([RFC 6026 section 8.3]). Sending a late response through the reply
/// route instead would skip that check.
///
/// [RFC 3261 section 13.3.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4
/// [RFC 6026 section 8.3]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.3
pub struct Responder {
    pub(super) shared: Arc<Shared>,
    pub(super) route: ReplyRoute,
    pub(super) method: Method,
    pub(super) commands: mpsc::UnboundedSender<Command>,
    pub(super) drops: mpsc::UnboundedSender<(Arc<Shared>, ReplyRoute)>,
    pub(super) submissions: Budget,
}

impl fmt::Debug for Responder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Responder")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

impl Responder {
    /// Returns the identity of this server transaction.
    pub fn id(&self) -> ServerTransactionId {
        self.shared.id
    }

    /// Returns the received request method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns a clone of the request's [`ReplyRoute`], for responses outside
    /// the transaction, such as UAS 2xx retransmissions. The route counts
    /// against [`Builder::max_responder_handles`] until its last clone drops.
    ///
    /// [`Builder::max_responder_handles`]: super::Builder::max_responder_handles
    pub fn reply_route(&self) -> ReplyRoute {
        self.route.clone()
    }

    /// Submits a response and waits until the driver accepts it, which is not
    /// peer receipt.
    ///
    /// An INVITE takes provisional responses until its first final response.
    /// After a 2xx it takes further 2xx, including those of other forks with
    /// other To tags, until Timer L ([RFC 6026 section 8.7]). The transaction
    /// does not retransmit a 2xx itself. A non-INVITE takes one final response
    /// and the 100 that [RFC 4320 section 4] allows.
    ///
    /// An unpolled future has no effect. The first poll checks the response
    /// against the request, reserves its encoded size and enqueues it. A
    /// dropped future does not withdraw an enqueued response. Later write
    /// failures arrive through [`ServerEvents`].
    ///
    /// # Errors
    ///
    /// Returns a [`SubmitError`]. Every variant except `Closed` leaves the
    /// transaction unchanged, and `Busy`, `RetentionFull`, `TransportBusy` and
    /// `TooEarly` can succeed later. `Closed` can follow an enqueued
    /// submission, so the response may or may not have been accepted.
    ///
    /// # Example
    ///
    /// A UAS rings and then answers an INVITE, with one To tag for the
    /// dialog on both responses.
    ///
    /// ```
    /// use bytes::Bytes;
    /// use signa::{
    ///     endpoint::Responder, message::header::Tag, Request, Response,
    /// };
    ///
    /// async fn answer(
    ///     responder: &Responder,
    ///     invite: &Request<Bytes>,
    /// ) -> Result<(), Box<dyn std::error::Error>> {
    ///     let tag = Tag::random();
    ///     let ringing = Response::reply_to(invite)
    ///         .status(180)
    ///         .to_tag(tag.clone())
    ///         .body(Bytes::new())?;
    ///     responder.respond(ringing).await?;
    ///
    ///     let ok = Response::reply_to(invite)
    ///         .status(200)
    ///         .to_tag(tag)
    ///         .header("Contact", "<sip:bob@192.0.2.4>")
    ///         .body(Bytes::new())?;
    ///     // Before this, the TU registers its wait for the ACK and takes a
    ///     // `WorkGuard`. After it, the TU retransmits the 2xx through
    ///     // `responder.reply_route()` until the ACK arrives.
    ///     responder.respond(ok).await?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [RFC 6026 section 8.7]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.7
    /// [RFC 4320 section 4]: https://www.rfc-editor.org/rfc/rfc4320.html#section-4
    pub fn respond(
        &self,
        response: Response<Bytes>,
    ) -> ResponseSubmission<'_> {
        let id = ResponseId {
            transaction: self.id(),
            sequence: self
                .shared
                .next_operation
                .fetch_add(1, Ordering::Relaxed),
        };
        ResponseSubmission {
            id,
            responder: self,
            response: Some(response),
            result: None,
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        if !self.shared.final_sent.load(Ordering::Acquire) {
            let _ = self.drops.send((self.shared.clone(), self.route.clone()));
        }
    }
}

/// The acceptance future of a response submission.
///
/// [`Responder::respond`] returns it. It is `Send` and `Unpin`, and both are
/// part of its API, so a response-sender wrapper outside signa can name it as
/// an associated type and poll it without boxing or pin projection.
#[must_use = "response submission has no effect until polled"]
pub struct ResponseSubmission<'a> {
    id: ResponseId,
    responder: &'a Responder,
    response: Option<Response<Bytes>>,
    result: Option<oneshot::Receiver<Result<(), SubmitError>>>,
}

impl ResponseSubmission<'_> {
    /// Returns the operation identifier used by later transport failure events.
    pub fn id(&self) -> ResponseId {
        self.id
    }
}

impl fmt::Debug for ResponseSubmission<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseSubmission").finish_non_exhaustive()
    }
}

impl Future for ResponseSubmission<'_> {
    type Output = Result<(), SubmitError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        if let Some(response) = self.response.take() {
            if self.responder.commands.is_closed() {
                return Poll::Ready(Err(SubmitError::Closed));
            }
            if self.responder.route.validate(&response).is_err() {
                return Poll::Ready(Err(SubmitError::InvalidResponse));
            }
            // A length that overflows `usize` is a property of the response,
            // so retrying cannot help.
            let Some(len) = response.encoded_len() else {
                return Poll::Ready(Err(SubmitError::InvalidResponse));
            };

            let Some(permit) = self.responder.submissions.acquire(len) else {
                return Poll::Ready(Err(SubmitError::Busy));
            };

            let status = response.status();
            let bytes = response.to_bytes_reserved(len);
            let (done, result) = oneshot::channel();
            self.responder.shared.pending.fetch_add(1, Ordering::Relaxed);
            let submission = Submission {
                shared: self.responder.shared.clone(),
                operation: self.id,
                status,
                bytes,
                done,
                _permit: permit,
            };
            if self
                .responder
                .commands
                .send(Command::Submit(submission))
                .is_err()
            {
                self.responder.shared.pending.fetch_sub(1, Ordering::Release);
                return Poll::Ready(Err(SubmitError::Closed));
            }
            self.result = Some(result);
        }

        Pin::new(self.result.as_mut().expect("submission was enqueued"))
            .poll(cx)
            .map(|result| result.unwrap_or(Err(SubmitError::Closed)))
    }
}

/// Why [`Responder::respond`] did not accept a response.
///
/// Every variant except `Closed` leaves the transaction unchanged. `Closed`
/// can follow an enqueued submission, so the response may or may not have been
/// accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SubmitError {
    /// Via, From, Call-ID or CSeq differs from the request, To is missing,
    /// changed or untagged where a tag is required, or the encoded length
    /// overflows. The response can never be accepted as it is.
    InvalidResponse,
    /// Over UDP, a non-INVITE transaction does not send 100 before the driver's
    /// automatic 100 is due (RFC 4320 section 4).
    TooEarly,
    /// A non-INVITE transaction does not send a provisional response other
    /// than 100, or a 408 (RFC 4320 section 4).
    ProhibitedStatus,
    /// A final response was already accepted, and this is not another 2xx
    /// for an INVITE in Accepted.
    FinalAlreadySent,
    /// The transaction has terminated.
    Terminated,
    /// The endpoint's submission queue is full. It holds up to 64 submissions
    /// and [`Builder::max_server_response_bytes`] of encoded responses waiting
    /// for the driver. A response larger than that limit always gets `Busy`.
    ///
    /// [`Builder::max_server_response_bytes`]: super::Builder::max_server_response_bytes
    Busy,
    /// Responses cached by server transactions for retransmission reach
    /// [`Builder::max_server_response_bytes`]. Completed UDP transactions
    /// hold theirs until Timer J.
    ///
    /// [`Builder::max_server_response_bytes`]: super::Builder::max_server_response_bytes
    RetentionFull,
    /// The transport cannot take the response now. The UDP or TCP write
    /// queue, the fallback budget, or the response connection slots are
    /// full. See [`Builder::udp_write_limits`], [`Builder::tcp_write_limits`]
    /// and [`Builder::fallback_limits`].
    ///
    /// [`Builder::udp_write_limits`]: super::Builder::udp_write_limits
    /// [`Builder::tcp_write_limits`]: super::Builder::tcp_write_limits
    /// [`Builder::fallback_limits`]: super::Builder::fallback_limits
    TransportBusy,
    /// The endpoint ended before acceptance could be confirmed.
    Closed,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidResponse => {
                "response identity does not match the request"
            }
            Self::TooEarly => "100 is not allowed yet on this transport",
            Self::ProhibitedStatus => {
                "this status is prohibited for a non-INVITE response"
            }
            Self::FinalAlreadySent => "a final response was already accepted",
            Self::Terminated => "the server transaction has terminated",
            Self::Busy => "the response submission queue is full",
            Self::RetentionFull => {
                "retained server responses are at their limit"
            }
            Self::TransportBusy => {
                "the transport cannot take the response now"
            }
            Self::Closed => "the endpoint has closed",
        })
    }
}

impl error::Error for SubmitError {}

/// An observation of a server transaction, independent of application work.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ServerEvent {
    /// A locally accepted write or reconnect failed.
    TransportFailure {
        /// The submitted response, or `None` for driver-generated output.
        operation: Option<ResponseId>,
        /// The original local transport error.
        error: Arc<io::Error>,
    },
    /// Local output capacity refused a response that the driver generated
    /// or retransmits, such as the automatic 100 or a cached response sent
    /// again for a request retransmission.
    ///
    /// Nothing was written for this attempt. The transaction stays live, so a
    /// later request retransmission can resend the cached response. This is
    /// local saturation, not a transport failure or a SIP timeout. A refused
    /// 500 after a responder drop ends the transaction instead, and
    /// `Terminated` follows.
    OutputRejected {
        /// The submitted response, or `None` for driver-generated output.
        operation: Option<ResponseId>,
    },
    /// More failures or rejections occurred than the observer consumed. The
    /// latest one follows.
    ObservationOverflow {
        /// Failures and rejections preceding the latest retained one.
        missed: u64,
    },
    /// An INVITE got no ACK for its non-2xx final response before Timer H.
    /// `Terminated` follows ([RFC 3261 section 17.2.1]).
    ///
    /// [RFC 3261 section 17.2.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.1
    AckTimeout,
    /// The transaction ended. A non-INVITE ends at Timer J over UDP, at the
    /// final response over TCP, or after a transport failure. An INVITE ends
    /// at Timer I after its ACK over UDP, at the ACK over TCP, at Timer H
    /// without one, or at Timer L after a 2xx. An INVITE transport failure
    /// does not end it ([RFC 6026 section 8.8]). Writes already accepted may
    /// still report failures before the stream ends.
    ///
    /// [RFC 6026 section 8.8]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.8
    Terminated,
    /// The endpoint ended before transaction observation completed.
    EndpointClosed,
}

// The reserved terminal slot holds only a reason, not another copy of the
// much larger transport-failure variant. This state is retained for Timer J.
#[derive(Clone, Copy, Debug)]
pub(super) enum End {
    Terminated,
    EndpointClosed,
}

/// The latest output problem. Only one is retained, and `failures` counts
/// every problem so that the observer can report how many it missed.
#[derive(Clone, Debug)]
pub(super) enum Problem {
    Transport(Arc<io::Error>),
    Rejected,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Observation {
    pub(super) failures: u64,
    pub(super) ack_timeout: bool,
    pub(super) terminated: bool,
    pub(super) problem: Option<Problem>,
    pub(super) operation: Option<ResponseId>,
    pub(super) end: Option<End>,
}

/// Observes one server transaction's write failures, refused output and
/// termination.
///
/// It keeps the latest failure and counts the rest, so it never blocks the
/// driver, and termination is never lost. Dropping it has no protocol effect.
#[derive(Debug)]
pub struct ServerEvents {
    pub(super) id: ServerTransactionId,
    pub(super) receiver: watch::Receiver<Observation>,
    pub(super) seen: u64,
    pub(super) ended: bool,
    pub(super) saw_ack_timeout: bool,
    pub(super) saw_termination: bool,
}

impl ServerEvents {
    /// Returns the identity of the observed server transaction.
    pub fn id(&self) -> ServerTransactionId {
        self.id
    }

    /// Receives the next event, or `None` once the stream ends.
    ///
    /// It is cancellation-safe. Failures already recorded, then `AckTimeout`,
    /// come before `Terminated`. After `Terminated`, failures of writes
    /// already accepted can still arrive. The stream then ends, or yields
    /// `EndpointClosed` if the endpoint stops first. It returns `None` from
    /// then on.
    ///
    /// # Example
    ///
    /// An observer that logs what became of a transaction's responses. It
    /// can run in a task of its own while the handler goes on, or not at all.
    ///
    /// ```
    /// use signa::endpoint::{ServerEvent, ServerEvents};
    ///
    /// async fn observe(mut events: ServerEvents) {
    ///     while let Some(event) = events.next().await {
    ///         match event {
    ///             ServerEvent::TransportFailure { operation, error } => {
    ///                 eprintln!("write of {operation:?} failed: {error}");
    ///             }
    ///             // A non-2xx final response to an INVITE got no ACK.
    ///             ServerEvent::AckTimeout => eprintln!("no ACK"),
    ///             // Later failures of accepted writes can still follow.
    ///             ServerEvent::Terminated => {}
    ///             other => eprintln!("{other:?}"),
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn next(&mut self) -> Option<ServerEvent> {
        loop {
            if self.ended {
                return None;
            }

            {
                let state = self.receiver.borrow_and_update();
                if state.failures > self.seen.saturating_add(1) {
                    let missed = state.failures - self.seen - 1;
                    self.seen = state.failures - 1;
                    return Some(ServerEvent::ObservationOverflow { missed });
                }
                if state.failures > self.seen {
                    self.seen = state.failures;
                    let operation = state.operation;
                    return Some(match &state.problem {
                        Some(Problem::Transport(error)) => {
                            ServerEvent::TransportFailure {
                                operation,
                                error: error.clone(),
                            }
                        }
                        Some(Problem::Rejected) | None => {
                            ServerEvent::OutputRejected { operation }
                        }
                    });
                }
                if state.ack_timeout && !self.saw_ack_timeout {
                    self.saw_ack_timeout = true;
                    return Some(ServerEvent::AckTimeout);
                }
                if state.terminated && !self.saw_termination {
                    self.saw_termination = true;
                    return Some(ServerEvent::Terminated);
                }
                if let Some(end) = &state.end {
                    self.ended = true;
                    return match end {
                        End::Terminated => None,
                        End::EndpointClosed => {
                            Some(ServerEvent::EndpointClosed)
                        }
                    };
                }
            }

            if self.receiver.changed().await.is_err() {
                self.ended = true;
                return Some(ServerEvent::EndpointClosed);
            }
        }
    }
}

/// An application-work reservation that ends at an accepted final response or
/// termination, whichever comes first, while its holder may live longer.
pub(super) struct Work(Mutex<Option<Permit>>);

impl Work {
    pub(super) fn new(permit: Permit) -> Work {
        Work(Mutex::new(Some(permit)))
    }

    pub(super) fn finish(&self) {
        self.0.lock().expect("work reservation is not poisoned").take();
    }
}

pub(super) struct Shared {
    pub(super) id: ServerTransactionId,
    pub(super) slot: Id,
    pub(super) work: Work,
    pub(super) pending: AtomicUsize,
    pub(super) next_operation: std::sync::atomic::AtomicU64,
    pub(super) final_sent: AtomicBool,
    pub(super) abandoned: AtomicBool,
    pub(super) observation: watch::Sender<Observation>,
    pub(super) transport: AtomicUsize,
    pub(super) terminated: AtomicBool,
}

impl Shared {
    /// Reports driver-generated output that local capacity refused.
    pub(super) fn rejected(&self) {
        self.problem(None, Problem::Rejected);
    }

    fn problem(&self, operation: Option<ResponseId>, problem: Problem) {
        if self.observation.receiver_count() == 0 {
            return;
        }
        self.observation.send_modify(|state| {
            state.operation = operation;
            state.failures = state.failures.saturating_add(1);
            state.problem = Some(problem);
        });
    }

    /// Records Timer H. The caller then finishes the transaction.
    pub(super) fn ack_timeout(&self) {
        if self.observation.receiver_count() != 0 {
            self.observation.send_modify(|state| state.ack_timeout = true);
        }
    }

    pub(super) fn finish(&self) {
        self.work.finish();
        self.terminated.store(true, Ordering::Release);
        if self.observation.receiver_count() != 0 {
            let drained = self.transport.load(Ordering::Acquire) == 0;
            self.observation.send_modify(|state| {
                state.terminated = true;
                if drained && state.end.is_none() {
                    state.end = Some(End::Terminated);
                }
            });
        }
    }

    fn end_if_drained(&self) {
        if self.observation.receiver_count() != 0
            && self.terminated.load(Ordering::Acquire)
            && self.transport.load(Ordering::Acquire) == 0
        {
            self.observation.send_modify(|state| {
                if state.end.is_none() {
                    state.end = Some(End::Terminated);
                }
            });
        }
    }

    pub(super) fn write(
        self: &Arc<Self>,
        operation: Option<ResponseId>,
    ) -> WriteObservation {
        self.transport.fetch_add(1, Ordering::Relaxed);
        WriteObservation {
            shared: self.clone(),
            operation,
            completed: false,
            fallback: None,
        }
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.work.finish();
    }
}

pub(super) struct WriteObservation {
    shared: Arc<Shared>,
    operation: Option<ResponseId>,
    completed: bool,
    fallback: Option<Arc<super::driver::ConnectionCounters>>,
}

impl WriteObservation {
    pub(super) fn fallback(
        mut self,
        counters: Arc<super::driver::ConnectionCounters>,
    ) -> WriteObservation {
        self.fallback = Some(counters);
        self
    }

    pub(super) fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    pub(super) fn complete(mut self, result: io::Result<()>) {
        if let Err(error) = result {
            if let Some(counters) = &self.fallback {
                super::driver::increment(&counters.dropped);
            }
            self.shared
                .problem(self.operation, Problem::Transport(Arc::new(error)));
        }
        self.completed = true;
    }

    /// Ends a committed write that local capacity refused before any byte
    /// reached a socket.
    pub(super) fn reject(mut self) {
        if let Some(counters) = &self.fallback {
            super::driver::increment(&counters.dropped);
        }
        self.shared.problem(self.operation, Problem::Rejected);
        self.completed = true;
    }
}

impl Drop for WriteObservation {
    fn drop(&mut self) {
        if !self.completed {
            if let Some(counters) = &self.fallback {
                super::driver::increment(&counters.dropped);
            }
            // Teardown can stop observation while a socket still drains. It
            // cannot establish whether that write succeeded or failed.
            self.shared.observation.send_modify(|state| {
                if state.end.is_none() {
                    state.end = Some(End::EndpointClosed);
                }
            });
        }
        self.shared.transport.fetch_sub(1, Ordering::Release);
        self.shared.end_if_drained();
    }
}

pub(super) struct Submission {
    pub(super) shared: Arc<Shared>,
    pub(super) operation: ResponseId,
    pub(super) status: crate::StatusCode,
    // Teardown drops encoded content and its reservation before waking the
    // acceptance waiter by dropping the sender.
    pub(super) bytes: Bytes,
    pub(super) _permit: Permit,
    pub(super) done: oneshot::Sender<Result<(), SubmitError>>,
}

#[cfg(all(test, not(miri)))]
mod integration {
    use std::{future::poll_fn, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
        time::timeout,
    };

    use super::*;
    use crate::{
        endpoint::{
            tests::{route_request, route_response},
            Builder, Endpoint, ShutdownOutcome,
        },
        message::header::{HeaderValue, TO, VIA},
        transport::WriteLimits,
    };

    async fn udp(builder: Builder) -> (Endpoint, Incoming, UdpSocket) {
        let (endpoint, incoming) =
            builder.udp("127.0.0.1:0".parse().unwrap()).bind().unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        (endpoint, incoming, peer)
    }

    async fn send(peer: &UdpSocket, endpoint: &Endpoint, branch: &str) {
        let via = format!(
            "SIP/2.0/UDP {};branch=z9hG4bK{branch};rport",
            peer.local_addr().unwrap()
        );
        peer.send_to(
            &route_request(&via).to_bytes(),
            endpoint.udp_addr().unwrap(),
        )
        .await
        .unwrap();
    }

    async fn request(incoming: &mut Incoming) -> ServerRequest {
        let event = timeout(Duration::from_secs(1), incoming.recv())
            .await
            .unwrap()
            .unwrap();
        let IncomingEvent::Request(request) = event else {
            panic!("tracked request");
        };

        request
    }

    async fn observe(events: &mut ServerEvents) -> Option<ServerEvent> {
        timeout(Duration::from_secs(1), events.next()).await.unwrap()
    }

    async fn response(peer: &UdpSocket) -> Response<Bytes> {
        let mut bytes = vec![0; 8192];
        let n = timeout(Duration::from_secs(1), peer.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();

        Response::from_bytes(&bytes[..n]).unwrap()
    }

    #[tokio::test]
    async fn work_lasts_beyond_recv_and_returns_at_accepted_final() {
        let (endpoint, mut incoming, peer) =
            udp(Endpoint::builder().max_pending_requests(1)).await;
        send(&peer, &endpoint, "first").await;
        let envelope = request(&mut incoming).await;
        assert!(envelope
            .request
            .extensions()
            .get::<crate::transport::Flow>()
            .is_none());
        let (responder, _events) = envelope.transaction.into_parts();

        send(&peer, &endpoint, "second").await;
        assert_eq!(response(&peer).await.status().as_u16(), 503);
        responder.respond(route_response(&envelope.request)).await.unwrap();
        assert_eq!(response(&peer).await.status().as_u16(), 200);

        // Keep the completed responder alive. Its separate route reservation
        // must not retain the application-work reservation.
        send(&peer, &endpoint, "third").await;
        let next = request(&mut incoming).await;
        assert_ne!(next.transaction.id(), responder.id());
        assert_eq!(
            responder.respond(route_response(&envelope.request)).await,
            Err(SubmitError::FinalAlreadySent)
        );
    }

    #[tokio::test]
    async fn a_retained_route_has_its_own_lifetime_bound() {
        let (endpoint, mut incoming, peer) =
            udp(Endpoint::builder().max_responder_handles(1)).await;
        send(&peer, &endpoint, "first").await;
        let envelope = request(&mut incoming).await;
        let (responder, _) = envelope.transaction.into_parts();
        let route = responder.reply_route();
        responder.respond(route_response(&envelope.request)).await.unwrap();
        drop(responder);
        assert_eq!(response(&peer).await.status().as_u16(), 200);

        send(&peer, &endpoint, "second").await;
        assert_eq!(response(&peer).await.status().as_u16(), 503);
        drop(route);

        send(&peer, &endpoint, "third").await;
        let _request = request(&mut incoming).await;
    }

    #[tokio::test]
    async fn cancelled_waiter_and_responder_drop_cannot_race_a_queued_final() {
        let (endpoint, mut incoming, peer) = udp(Endpoint::builder()).await;
        send(&peer, &endpoint, "first").await;
        let envelope = request(&mut incoming).await;
        let (responder, _) = envelope.transaction.into_parts();
        let reply = route_response(&envelope.request);

        let mut submission = responder.respond(reply);
        poll_fn(|cx| {
            assert!(Pin::new(&mut submission).poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(submission);
        drop(responder);

        assert_eq!(response(&peer).await.status().as_u16(), 200);
        let mut bytes = [0; 8192];
        assert!(timeout(Duration::from_millis(20), peer.recv(&mut bytes))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn response_rejections_preserve_the_live_machine() {
        let (endpoint, mut incoming, peer) = udp(Endpoint::builder()).await;
        send(&peer, &endpoint, "first").await;
        let envelope = request(&mut incoming).await;
        let (responder, events) = envelope.transaction.into_parts();
        assert_eq!(events.id(), responder.id());
        let mut invalid = route_response(&envelope.request);
        invalid.headers_mut().remove(VIA);
        assert_eq!(
            responder.respond(invalid).await,
            Err(SubmitError::InvalidResponse)
        );

        for status in [180, 408] {
            let mut reply = route_response(&envelope.request);
            *reply.status_mut() = crate::StatusCode::from_u16(status).unwrap();
            assert_eq!(
                responder.respond(reply).await,
                Err(SubmitError::ProhibitedStatus)
            );
        }
        let trying = Response::reply_to(&envelope.request)
            .status(100)
            .body(Bytes::new())
            .unwrap();
        assert_eq!(
            responder.respond(trying).await,
            Err(SubmitError::TooEarly)
        );

        let submission = responder.respond(route_response(&envelope.request));
        assert_eq!(submission.id().transaction(), responder.id());
        submission.await.unwrap();
        assert_eq!(response(&peer).await.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn accepted_io_failure_precedes_termination_and_retains_operation_id(
    ) {
        let (endpoint, mut incoming, peer) = udp(Endpoint::builder()).await;
        send(&peer, &endpoint, "io-failure").await;
        let envelope = request(&mut incoming).await;
        let (responder, mut events) = envelope.transaction.into_parts();
        let mut reply = route_response(&envelope.request);
        // This fits the byte quotas but exceeds the UDP payload maximum.
        *reply.body_mut() = Bytes::from(vec![0; 80 * 1024]);
        let submission = responder.respond(reply);
        let operation = submission.id();

        submission.await.unwrap();

        let Some(ServerEvent::TransportFailure { operation: failed, error }) =
            observe(&mut events).await
        else {
            panic!("write failure");
        };
        assert_eq!(failed, Some(operation));
        assert!(error.raw_os_error().is_some());
        assert!(matches!(
            observe(&mut events).await,
            Some(ServerEvent::Terminated)
        ));
        assert!(observe(&mut events).await.is_none());
    }

    #[tokio::test]
    async fn transport_quota_rejection_does_not_commit_a_final_response() {
        let (endpoint, mut incoming, peer) = udp(Endpoint::builder()
            .udp_write_limits(WriteLimits { messages: 1, bytes: 1 }))
        .await;
        send(&peer, &endpoint, "quota").await;
        let envelope = request(&mut incoming).await;
        let (responder, mut events) = envelope.transaction.into_parts();

        assert_eq!(
            responder.respond(route_response(&envelope.request)).await,
            Err(SubmitError::TransportBusy)
        );
        assert!(timeout(Duration::from_millis(10), events.next())
            .await
            .is_err());
        drop(responder);

        assert!(matches!(
            observe(&mut events).await,
            Some(ServerEvent::OutputRejected { operation: None })
        ));
        assert!(matches!(
            observe(&mut events).await,
            Some(ServerEvent::Terminated)
        ));
    }

    #[tokio::test]
    async fn local_output_rejection_keeps_the_machine_and_its_request_key() {
        let timers = crate::transaction::Timers::builder()
            .t1(Duration::from_millis(1))
            .t2(Duration::from_millis(4))
            .t4(Duration::from_millis(5))
            .build()
            .unwrap();
        let (endpoint, mut incoming, peer) = udp(Endpoint::builder()
            .timers(timers)
            .udp_write_limits(WriteLimits { messages: 1, bytes: 1 }))
        .await;
        send(&peer, &endpoint, "saturated").await;
        let envelope = request(&mut incoming).await;
        let (responder, mut events) = envelope.transaction.into_parts();

        // The automatic 100 cannot be admitted.
        assert!(matches!(
            observe(&mut events).await,
            Some(ServerEvent::OutputRejected { operation: None })
        ));
        // Its cached copy cannot be resent either. The retransmission is
        // absorbed rather than starting a second transaction.
        send(&peer, &endpoint, "saturated").await;

        assert!(matches!(
            observe(&mut events).await,
            Some(ServerEvent::OutputRejected { operation: None })
        ));
        assert!(timeout(Duration::from_millis(20), incoming.recv())
            .await
            .is_err());
        assert_eq!(
            responder.respond(route_response(&envelope.request)).await,
            Err(SubmitError::TransportBusy)
        );
    }

    #[tokio::test]
    async fn saturated_response_retention_rejects_without_changing_state() {
        let (endpoint, mut incoming, peer) =
            udp(Endpoint::builder().max_server_response_bytes(1)).await;
        send(&peer, &endpoint, "first").await;
        let envelope = request(&mut incoming).await;
        let (responder, mut events) = envelope.transaction.into_parts();

        assert_eq!(
            responder.respond(route_response(&envelope.request)).await,
            Err(SubmitError::Busy)
        );
        drop(responder);

        assert!(matches!(
            observe(&mut events).await,
            Some(ServerEvent::OutputRejected { operation: None })
        ));
        assert!(matches!(
            observe(&mut events).await,
            Some(ServerEvent::Terminated)
        ));
        send(&peer, &endpoint, "next").await;
        let _next = request(&mut incoming).await;
    }

    #[tokio::test]
    async fn untracked_reception_has_no_transaction_or_drop_fallback() {
        let timers = crate::transaction::Timers::builder()
            .t1(Duration::from_millis(1))
            .t2(Duration::from_millis(4))
            .t4(Duration::from_millis(5))
            .build()
            .unwrap();
        let (endpoint, mut incoming, peer) =
            udp(Endpoint::builder().timers(timers)).await;
        let wire = route_request(&format!(
            "SIP/2.0/UDP {};branch=legacy;rport",
            peer.local_addr().unwrap()
        ))
        .to_bytes();

        for _ in 0..2 {
            peer.send_to(&wire, endpoint.udp_addr().unwrap()).await.unwrap();
            let event = timeout(Duration::from_secs(1), incoming.recv())
                .await
                .unwrap()
                .unwrap();
            let IncomingEvent::Untracked(envelope) = event else {
                panic!("untracked request");
            };
            assert_eq!(envelope.flow.remote, peer.local_addr().unwrap());
            drop(envelope);
        }

        let mut bytes = [0; 4096];
        assert!(timeout(Duration::from_millis(20), peer.recv(&mut bytes))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn untracked_work_ends_at_the_first_final_while_the_route_lives() {
        let (endpoint, mut incoming, peer) =
            udp(Endpoint::builder().max_pending_requests(1)).await;
        let untracked = |branch: &str| {
            route_request(&format!(
                "SIP/2.0/UDP {};branch={branch};rport",
                peer.local_addr().unwrap()
            ))
            .to_bytes()
        };
        peer.send_to(&untracked("first"), endpoint.udp_addr().unwrap())
            .await
            .unwrap();
        let event = timeout(Duration::from_secs(1), incoming.recv())
            .await
            .unwrap()
            .unwrap();
        let IncomingEvent::Untracked(envelope) = event else {
            panic!("untracked request");
        };
        let kept = envelope.reply.clone();

        envelope.reply.send(route_response(&envelope.request)).await.unwrap();
        drop(envelope);
        assert_eq!(response(&peer).await.status().as_u16(), 200);

        // The kept clone no longer holds the only work permit.
        send(&peer, &endpoint, "tracked").await;
        let _next = request(&mut incoming).await;
        drop(kept);
    }

    #[tokio::test]
    async fn new_tu_capacities_must_be_positive_at_bind() {
        for builder in [
            Endpoint::builder().max_pending_requests(0),
            Endpoint::builder().max_server_request_bytes(0),
            Endpoint::builder().max_responder_handles(0),
            Endpoint::builder().max_responder_bytes(0),
            Endpoint::builder().max_server_response_bytes(0),
        ] {
            let error = builder.bind().unwrap_err();
            assert!(error.is_invalid_config());
            assert!(error.to_string().ends_with("must be positive"));
            assert_eq!(
                io::Error::from(error).kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[tokio::test]
    async fn a_panicking_application_releases_work_through_responder_drop() {
        let (endpoint, mut incoming, peer) =
            udp(Endpoint::builder().max_pending_requests(1)).await;
        send(&peer, &endpoint, "panic").await;
        let envelope = request(&mut incoming).await;

        let application = tokio::spawn(async move {
            let _transaction = envelope.transaction;
            panic!("application handler failed");
        });
        assert!(application.await.unwrap_err().is_panic());

        let fallback = response(&peer).await;
        assert_eq!(fallback.status().as_u16(), 500);
        assert!(crate::message::header::address::has_tag(
            fallback.headers().get(TO).unwrap().as_str()
        ));
        send(&peer, &endpoint, "after-panic").await;
        let _next = request(&mut incoming).await;
    }

    #[tokio::test]
    async fn malformed_request_identity_never_consumes_tu_admission() {
        let (endpoint, mut incoming, peer) =
            udp(Endpoint::builder().max_pending_requests(1)).await;
        let via = format!(
            "SIP/2.0/UDP {};branch=z9hG4bKidentity;rport",
            peer.local_addr().unwrap()
        );
        let mut malformed = route_request(&via);
        malformed.headers_mut().insert(
            crate::message::header::CSEQ,
            HeaderValue::from_static("1 INVITE"),
        );

        peer.send_to(&malformed.to_bytes(), endpoint.udp_addr().unwrap())
            .await
            .unwrap();

        assert_eq!(response(&peer).await.status().as_u16(), 400);
        assert!(timeout(Duration::from_millis(20), incoming.recv())
            .await
            .is_err());
        let mut repeated = route_request(&via);
        repeated
            .headers_mut()
            .append(TO, HeaderValue::from_static("<sip:carol@example.com>"));
        peer.send_to(&repeated.to_bytes(), endpoint.udp_addr().unwrap())
            .await
            .unwrap();
        assert_eq!(response(&peer).await.status().as_u16(), 400);

        peer.send_to(
            &route_request(&via).to_bytes(),
            endpoint.udp_addr().unwrap(),
        )
        .await
        .unwrap();
        let _valid = request(&mut incoming).await;
    }

    #[tokio::test]
    async fn via_maddr_requests_are_dropped_without_multicast_support() {
        let (endpoint, mut incoming, peer) = udp(Endpoint::builder()).await;
        let via = format!(
            "SIP/2.0/UDP {};branch=z9hG4bKmaddr;maddr=224.0.1.75;rport",
            peer.local_addr().unwrap()
        );

        peer.send_to(
            &route_request(&via).to_bytes(),
            endpoint.udp_addr().unwrap(),
        )
        .await
        .unwrap();

        let mut bytes = [0; 4096];
        assert!(timeout(Duration::from_millis(20), peer.recv(&mut bytes))
            .await
            .is_err());
        assert!(timeout(Duration::from_millis(1), incoming.recv())
            .await
            .is_err());
    }

    async fn tcp_response(stream: &mut TcpStream) -> Response<Bytes> {
        let mut bytes = Vec::new();
        timeout(Duration::from_secs(1), async {
            while !bytes.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).await.unwrap();
                bytes.push(byte[0]);
            }
        })
        .await
        .unwrap();

        Response::from_bytes(&bytes).unwrap()
    }

    #[tokio::test]
    async fn final_replaces_provisional_within_retained_budget() {
        let (endpoint, mut incoming) = Endpoint::builder()
            .max_server_response_bytes(512)
            .tcp("127.0.0.1:0".parse().unwrap())
            .bind()
            .unwrap();
        let mut peer =
            TcpStream::connect(endpoint.tcp_addr().unwrap()).await.unwrap();
        let via = format!(
            "SIP/2.0/TCP {};branch=z9hG4bKreplace",
            peer.local_addr().unwrap()
        );
        peer.write_all(&route_request(&via).to_bytes()).await.unwrap();
        let envelope = request(&mut incoming).await;
        let (responder, _events) = envelope.transaction.into_parts();
        let mut trying = route_response(&envelope.request);
        *trying.status_mut() = crate::StatusCode::from_u16(100).unwrap();
        *trying.body_mut() = Bytes::from(vec![b'x'; 200]);
        let mut final_response = route_response(&envelope.request);
        *final_response.body_mut() = Bytes::from(vec![b'x'; 200]);
        assert!(trying.to_bytes().len() <= 512);
        assert!(final_response.to_bytes().len() <= 512);
        assert!(
            trying.to_bytes().len() + final_response.to_bytes().len() > 512
        );
        responder.respond(trying).await.unwrap();
        assert_eq!(responder.respond(final_response).await, Ok(()));
    }

    #[tokio::test]
    async fn unanswered_drop_reuses_the_provisional_to_tag() {
        let (endpoint, mut incoming) = Endpoint::builder()
            .tcp("127.0.0.1:0".parse().unwrap())
            .bind()
            .unwrap();
        let mut peer =
            TcpStream::connect(endpoint.tcp_addr().unwrap()).await.unwrap();
        let via = format!(
            "SIP/2.0/TCP {};branch=z9hG4bKdrop",
            peer.local_addr().unwrap()
        );
        peer.write_all(&route_request(&via).to_bytes()).await.unwrap();
        let envelope = request(&mut incoming).await;
        let (responder, mut events) = envelope.transaction.into_parts();
        let mut trying = route_response(&envelope.request);
        *trying.status_mut() = crate::StatusCode::from_u16(100).unwrap();
        let selected_to = HeaderValue::from_bytes(
            format!(
                "{};tag=chosen",
                envelope.request.headers().get(TO).unwrap().as_str()
            )
            .as_bytes(),
        )
        .unwrap();
        trying.headers_mut().insert(TO, selected_to.clone());

        responder.respond(trying).await.unwrap();
        assert_eq!(tcp_response(&mut peer).await.status().as_u16(), 100);
        drop(responder);

        let fallback = tcp_response(&mut peer).await;
        assert_eq!(fallback.status().as_u16(), 500);
        assert_eq!(fallback.headers().get(TO), Some(&selected_to));
        assert!(matches!(
            observe(&mut events).await,
            Some(ServerEvent::Terminated)
        ));
    }

    #[tokio::test]
    async fn dropping_incoming_starts_an_immediate_shutdown() {
        let (endpoint, mut incoming, peer) = udp(Endpoint::builder()).await;
        send(&peer, &endpoint, "live").await;
        let envelope = request(&mut incoming).await;
        let (responder, mut events) = envelope.transaction.into_parts();

        drop(incoming);

        assert!(matches!(
            observe(&mut events).await,
            Some(ServerEvent::EndpointClosed)
        ));
        // The earliest deadline wins, so a longer graceful request cannot
        // extend the drop's immediate one. The unanswered request was left.
        let outcome = timeout(
            Duration::from_secs(1),
            endpoint.shutdown(Duration::from_secs(60)),
        )
        .await;
        assert_eq!(outcome.unwrap(), ShutdownOutcome::DeadlineExpired);
        assert_eq!(
            responder.respond(route_response(&envelope.request)).await,
            Err(SubmitError::Closed)
        );
    }

    #[tokio::test]
    async fn forced_shutdown_and_receive_cancellation_are_explicit() {
        let (endpoint, mut incoming, peer) = udp(Endpoint::builder()).await;
        let mut waiting = Box::pin(incoming.recv());
        poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(waiting);

        send(&peer, &endpoint, "first").await;
        let envelope = request(&mut incoming).await;
        let (responder, mut events) = envelope.transaction.into_parts();
        assert_eq!(
            endpoint.shutdown(Duration::ZERO).await,
            ShutdownOutcome::DeadlineExpired
        );

        assert!(matches!(
            observe(&mut events).await,
            Some(ServerEvent::EndpointClosed)
        ));
        assert_eq!(
            responder.respond(route_response(&envelope.request)).await,
            Err(SubmitError::Closed)
        );
        assert!(incoming.recv().await.is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{endpoint::table::Table, transport::WriteLimits};

    fn observed() -> (Arc<Shared>, ServerEvents, Budget) {
        let budget = Budget::new(WriteLimits { messages: 1, bytes: 1 });
        let permit = budget.acquire(1).unwrap();
        let slot = Table::new().insert(1u8, ());
        let (observation, receiver) = watch::channel(Observation::default());
        let shared = Arc::new(Shared {
            id: ServerTransactionId(1),
            slot,
            work: Work::new(permit),
            pending: AtomicUsize::new(0),
            next_operation: std::sync::atomic::AtomicU64::new(1),
            final_sent: AtomicBool::new(false),
            abandoned: AtomicBool::new(false),
            observation,
            transport: AtomicUsize::new(0),
            terminated: AtomicBool::new(false),
        });
        let events = ServerEvents {
            id: ServerTransactionId(1),
            receiver,
            seen: 0,
            ended: false,
            saw_ack_timeout: false,
            saw_termination: false,
        };

        (shared, events, budget)
    }

    #[test]
    fn public_operations_are_send_and_envelopes_are_owned() {
        fn send<T: Send>() {}
        fn sync<T: Sync>() {}
        fn unpin<T: Unpin>() {}
        send::<Incoming>();
        send::<IncomingEvent>();
        send::<ResponseSubmission<'static>>();
        // Part of its API, so a wrapper can poll it in place.
        unpin::<ResponseSubmission<'static>>();
        send::<ServerTransaction>();
        sync::<Responder>();
    }

    #[test]
    fn local_write_failure_remains_observable_after_machine_termination() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let (shared, mut events, budget) = observed();
                let operation =
                    ResponseId { transaction: shared.id, sequence: 1 };
                let write = shared.write(Some(operation));

                shared.finish();

                assert!(budget.is_idle());
                assert!(events.receiver.borrow().end.is_none());
                assert!(matches!(
                    events.next().await,
                    Some(ServerEvent::Terminated)
                ));

                write.complete(Err(io::Error::from_raw_os_error(5)));

                let Some(ServerEvent::TransportFailure {
                    operation: failed,
                    error,
                }) = events.next().await
                else {
                    panic!("write failure");
                };
                assert_eq!(failed, Some(operation));
                assert_eq!(error.raw_os_error(), Some(5));
                assert!(events.next().await.is_none());
            });
    }

    #[test]
    fn teardown_reports_an_unknown_write_outcome_as_endpoint_close() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let (shared, mut events, _) = observed();
                let write = shared.write(None);
                shared.finish();

                drop(write);

                assert!(matches!(
                    events.next().await,
                    Some(ServerEvent::Terminated)
                ));
                assert!(matches!(
                    events.next().await,
                    Some(ServerEvent::EndpointClosed)
                ));
                assert!(events.next().await.is_none());
            });
    }

    #[test]
    fn fallback_drop_accounting_counts_failure_and_abandonment_once() {
        let (shared, _events, _) = observed();
        let counters =
            Arc::new(super::super::driver::ConnectionCounters::default());

        shared
            .write(None)
            .fallback(counters.clone())
            .complete(Err(io::Error::from_raw_os_error(5)));
        assert_eq!(counters.dropped.load(Ordering::Relaxed), 1);
        shared.write(None).fallback(counters.clone()).complete(Ok(()));
        assert_eq!(counters.dropped.load(Ordering::Relaxed), 1);
        drop(shared.write(None).fallback(counters.clone()));
        assert_eq!(counters.dropped.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn failure_overflow_does_not_consume_terminal_capacity() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let (shared, mut events, _) = observed();
                for code in [5, 6, 7] {
                    shared.problem(
                        None,
                        Problem::Transport(Arc::new(
                            io::Error::from_raw_os_error(code),
                        )),
                    );
                }
                shared.finish();

                assert!(matches!(
                    events.next().await,
                    Some(ServerEvent::ObservationOverflow { missed: 2 })
                ));
                let Some(ServerEvent::TransportFailure { error, .. }) =
                    events.next().await
                else {
                    panic!("latest failure");
                };
                assert_eq!(error.raw_os_error(), Some(7));
                assert!(matches!(
                    events.next().await,
                    Some(ServerEvent::Terminated)
                ));
                assert!(events.next().await.is_none());
            });
    }
}
