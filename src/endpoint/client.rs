/*!
Client transaction submission, cancellation and bounded response observation.
*/

use std::{
    collections::VecDeque,
    error, fmt,
    future::{Future, poll_fn},
    hash::{Hash, Hasher},
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use super::{
    Endpoint, Error, admission, builder::Reception, driver::Command, table::Id,
};
use crate::{
    message::{
        Method, Uri,
        header::{
            CALL_ID, CSEQ, FROM, HeaderName, HeaderValue, TO, address,
            cseq::CSeq,
        },
        request::Request,
        response::Response,
    },
    transport::{
        Flow, Transport, WriteLimits,
        budget::{Budget, Permit},
    },
};

/// An explicit next-hop address and transport.
///
/// The caller picks it after its own routing and RFC 3263 resolution.
/// [`Endpoint::start`] sends to it without comparing it with the request's
/// URIs. Its Routing section says what that leaves to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    transport: Transport,
    address: SocketAddr,
}

impl Target {
    /// Selects a transport and next hop without URI resolution.
    pub fn new(transport: Transport, address: SocketAddr) -> Target {
        Target { transport, address }
    }

    /// The selected transport.
    pub fn transport(self) -> Transport {
        self.transport
    }

    /// The selected next hop.
    pub fn address(self) -> SocketAddr {
        self.address
    }
}

/// An opaque transaction identity.
///
/// Retaining it prevents allocation reuse and retains one slot from
/// [`super::Builder::max_client_handles`].
#[derive(Clone)]
pub struct ClientTransactionId(Arc<Permit>);

impl PartialEq for ClientTransactionId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ClientTransactionId {}

impl Hash for ClientTransactionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

impl fmt::Debug for ClientTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClientTransactionId")
            .field(&Arc::as_ptr(&self.0))
            .finish()
    }
}

/// An accepted client transaction, independent of its response observation.
///
/// Dropping this handle does not cancel the request or stop retransmissions.
#[derive(Debug)]
pub struct ClientTransaction {
    control: ClientControl,
    responses: Responses,
}

impl ClientTransaction {
    /// Separates transaction metadata from cancellation-safe observation.
    pub fn into_parts(self) -> (ClientControl, Responses) {
        (self.control, self.responses)
    }
}

/// Metadata and cancellation for an accepted transaction.
///
/// Dropping it does not stop the machine or send a CANCEL. An INVITE is
/// cancelled only by [`ClientControl::cancel`].
#[derive(Debug)]
pub struct ClientControl {
    id: ClientTransactionId,
    via: HeaderValue,
    flow: Flow,
    cancel: Option<CancelHandle>,
    commands: mpsc::UnboundedSender<Command>,
}

impl ClientControl {
    /// The identity of this transaction.
    pub fn id(&self) -> ClientTransactionId {
        self.id.clone()
    }

    /// The generated top Via, including its fresh branch.
    pub fn via(&self) -> &HeaderValue {
        &self.via
    }

    /// The actual transport flow, including the selected local address.
    pub fn flow(&self) -> Flow {
        self.flow
    }

    /// Asks the driver to cancel this INVITE, and waits for the outcome.
    ///
    /// Each INVITE has one cancellation intent. The driver waits for a
    /// provisional response before it sends the CANCEL, since
    /// [RFC 3261 section 9.1] forbids one earlier. If a final response or the
    /// end of the transaction comes first, the outcome is
    /// [`CancelOutcome::NotNeeded`]. Otherwise the CANCEL copies the INVITE's
    /// Request-URI, From, To, Call-ID, CSeq number, Route values and top Via,
    /// goes to the INVITE's next hop and transport, and starts a separate
    /// non-INVITE transaction, which [`CancelOutcome::Sent`] returns. Over TCP
    /// it opens a new connection to that next hop if the INVITE's has closed.
    ///
    /// The CANCEL does not end the INVITE or its [`Responses`]. The INVITE
    /// usually ends with a 487, which signa acknowledges. A 2xx can still win
    /// the race. It is delivered as usual, and the TU must acknowledge it. If
    /// no final response arrives within 64 T1 of the CANCEL, signa stops
    /// waiting, ends the INVITE, and [`Responses`] yields
    /// [`Error::is_cancel_timeout`]. That deadline is this endpoint's
    /// implementation of the section's recommendation, not Timer B.
    ///
    /// # Cancellation
    ///
    /// An unpolled future does nothing. The first poll records the intent and
    /// queues it for the driver, which commits it. Dropping the future after
    /// that does not withdraw it. The driver still sends the CANCEL after the
    /// first provisional response, and that CANCEL transaction runs
    /// unobserved. Calling again then reports
    /// [`CancelError::AlreadyRequested`], without a second CANCEL.
    ///
    /// # Errors
    ///
    /// * [`CancelError::NotInvite`] for a transaction that is not an INVITE.
    /// * [`CancelError::AlreadyRequested`] for every call after the first.
    /// * [`CancelError::Busy`] or [`CancelError::Transport`] when a new TCP
    ///   connection to the next hop was needed and could not be admitted or
    ///   opened. Nothing was sent.
    /// * [`CancelError::Closed`] once the endpoint has stopped.
    ///
    /// # Example
    ///
    /// signa has no ringing limit of its own, so the TU sets one. The control
    /// cancels in a task of its own while the caller goes on reading
    /// responses, since `cancel` waits for a provisional response first.
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use bytes::Bytes;
    /// use signa::{
    ///     endpoint::{CancelOutcome, ClientTransaction},
    ///     Response,
    /// };
    ///
    /// // Builds and sends the ACK for a 2xx, as the `Responses` example does.
    /// async fn acknowledge(_response: &Response<Bytes>) {}
    ///
    /// // Returns the INVITE's first final status, if it got one.
    /// async fn call(
    ///     invite: ClientTransaction,
    ///     ringing: Duration,
    /// ) -> Option<u16> {
    ///     let (control, mut responses) = invite.into_parts();
    ///     let canceller = tokio::spawn(async move {
    ///         tokio::time::sleep(ringing).await;
    ///         match control.cancel().await {
    ///             // The CANCEL runs as a transaction of its own, here
    ///             // unobserved. Its 200 does not end the INVITE.
    ///             Ok(CancelOutcome::Sent(_cancel)) => {}
    ///             // A final response came first.
    ///             Ok(_) => {}
    ///             Err(error) => eprintln!("no CANCEL sent: {error}"),
    ///         }
    ///     });
    ///
    ///     let mut status = None;
    ///     while let Some(Ok(response)) = responses.next().await {
    ///         if response.status().is_final() && status.is_none() {
    ///             status = Some(response.status().as_u16());
    ///             // Aborting cannot withdraw a cancellation already
    ///             // asked for.
    ///             canceller.abort();
    ///         }
    ///         // A 2xx can still win the race with the CANCEL. The TU
    ///         // acknowledges it and every later 2xx, so it reads on until
    ///         // Timer M ends the stream. A non-2xx, usually a 487, is
    ///         // signa's to acknowledge, and the stream ends after it.
    ///         if response.status().is_success() {
    ///             acknowledge(&response).await;
    ///         }
    ///     }
    ///     status
    /// }
    /// ```
    ///
    /// [RFC 3261 section 9.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn cancel(
        &self,
    ) -> impl Future<Output = Result<CancelOutcome, CancelError>> + Send + '_
    {
        async move {
            let handle = self.cancel.as_ref().ok_or(CancelError::NotInvite)?;
            if handle.intent.requested.swap(true, Ordering::AcqRel) {
                return Err(CancelError::AlreadyRequested);
            }

            let (done, outcome) = oneshot::channel();
            self.commands
                .send(Command::Cancel {
                    id: handle.id,
                    intent: handle.intent.clone(),
                    done,
                })
                .map_err(|_| CancelError::Closed)?;
            outcome.await.unwrap_or(Err(CancelError::Closed))
        }
    }
}

/// What [`ClientControl::cancel`] did.
#[derive(Debug)]
#[non_exhaustive]
pub enum CancelOutcome {
    /// The CANCEL was handed to its own client transaction, which sent it or
    /// reports why it could not through its [`Responses`]. This is not
    /// receipt by the peer.
    Sent(ClientTransaction),
    /// A final response arrived, or the INVITE ended, before a CANCEL could
    /// be sent. Nothing was sent.
    NotNeeded,
}

/// Why [`ClientControl::cancel`] sent no CANCEL.
#[derive(Debug)]
#[non_exhaustive]
pub enum CancelError {
    /// The transaction is not an INVITE. signa cancels only INVITEs.
    NotInvite,
    /// An earlier call recorded the intent. No second CANCEL is created.
    AlreadyRequested,
    /// A new TCP connection to the next hop could not be admitted.
    Busy,
    /// A new TCP connection to the next hop could not be opened.
    Transport(io::Error),
    /// The endpoint has stopped.
    Closed,
}

impl fmt::Display for CancelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInvite => f.write_str("only an INVITE can be cancelled"),
            Self::AlreadyRequested => {
                f.write_str("cancellation was already requested")
            }
            Self::Busy => {
                f.write_str("no connection to the next hop could be admitted")
            }
            Self::Transport(error) => {
                write!(f, "the next hop could not be reached: {error}")
            }
            Self::Closed => f.write_str("the endpoint is closed"),
        }
    }
}

impl error::Error for CancelError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

/// What `cancel` needs to find its INVITE in the driver. The intent is shared
/// with the driver's entry, which compares it before acting, so a reused table
/// slot cannot take a stale request.
#[derive(Debug)]
pub(super) struct CancelHandle {
    id: Id,
    intent: Arc<Intent>,
}

/// One INVITE's single cancellation intent.
#[derive(Debug, Default)]
pub(super) struct Intent {
    requested: AtomicBool,
}

impl CancelHandle {
    pub(super) fn new(id: Id, intent: Arc<Intent>) -> CancelHandle {
        CancelHandle { id, intent }
    }
}

/// Responses accepted by the transaction machine, in arrival order.
///
/// Every accepted provisional response is observable. A non-INVITE final, or
/// a non-2xx INVITE final, ends observation even while the machine stays to
/// absorb retransmissions and, for the INVITE, to acknowledge them. See
/// [RFC 3261 sections 17.1.1 and 17.1.2].
///
/// An INVITE 2xx does not end observation. Every 2xx the machine accepts,
/// including retransmissions and the 2xx of other forks with other To tags,
/// arrives until Timer M, 64 T1 after the first ([RFC 6026 section 8.4]).
/// Further 2xx do not restart Timer M, and the stream ends without an error
/// when it fires. signa does not merge 2xx by To tag. The TU sends the ACK
/// for each 2xx, for example with [`Endpoint::send_request`]. Dropping the
/// observation of an INVITE leaves later 2xx without anyone to acknowledge
/// them, and the UAS eventually gives up on the dialog.
///
/// # Overflow
///
/// Each stream is bounded by [`Builder::client_response_limits`] and shares
/// [`Builder::client_response_budget`] with the others. Overflow preserves
/// queued responses and then yields one explicit error. The machine goes on,
/// acknowledging a non-2xx and keeping an INVITE in Accepted until Timer M,
/// but nothing more is observed. A truncated set of 2xx is never presented
/// as a complete one.
///
/// # Cancellation
///
/// Receiving is cancellation-safe and fused. Dropping observation never
/// cancels SIP work.
///
/// # Example
///
/// A UAC follows its INVITE past the first 2xx and acknowledges each one.
///
/// ```
/// use bytes::Bytes;
/// use signa::{
///     endpoint::{Endpoint, Error, Responses, Target, ViaMode},
///     Request, Response,
/// };
///
/// // The UAC core builds the ACK and picks its next hop from the dialog that
/// // the 2xx creates, with the 2xx's To tag and the dialog's route set.
/// fn ack_for(_response: &Response<Bytes>) -> (Request<Bytes>, Target) {
///     todo!()
/// }
///
/// async fn follow(
///     endpoint: &Endpoint,
///     mut responses: Responses,
/// ) -> Result<(), Error> {
///     while let Some(response) = responses.next().await {
///         let response = response?;
///         if response.status().is_success() {
///             // A retransmission and another fork's 2xx need an ACK as
///             // well. It goes without a client transaction.
///             let (ack, target) = ack_for(&response);
///             endpoint.send_request(ack, target, ViaMode::Fresh).await?;
///         }
///     }
///     // A non-2xx final, or Timer M after a 2xx, ended the stream.
///     Ok(())
/// }
/// ```
///
/// [RFC 3261 sections 17.1.1 and 17.1.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1
/// [RFC 6026 section 8.4]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.4
/// [`Builder::client_response_limits`]: super::Builder::client_response_limits
/// [`Builder::client_response_budget`]: super::Builder::client_response_budget
pub struct Responses {
    shared: Arc<Mutex<State>>,
}

impl Responses {
    fn new(budget: Budget, limits: WriteLimits, handle: Permit) -> Responses {
        Responses {
            shared: Arc::new(Mutex::new(State {
                queue: VecDeque::new(),
                bytes: 0,
                terminal: None,
                ended: false,
                detached: false,
                waker: None,
                budget,
                limits,
                _handle: Arc::new(handle),
            })),
        }
    }

    /// Waits for the next response or terminal error.
    ///
    /// Dropping this future consumes nothing. After `None`, every subsequent
    /// call returns `None`.
    #[allow(clippy::should_implement_trait)] // A stream, not an Iterator.
    pub fn next(
        &mut self,
    ) -> impl Future<Output = Option<Result<Response<Bytes>, Error>>> + Send + '_
    {
        poll_fn(|cx| self.poll_next(cx))
    }

    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Response<Bytes>, Error>>> {
        let mut state =
            self.shared.lock().expect("response state is not poisoned");
        if let Some(queued) = state.queue.pop_front() {
            state.bytes -= queued.bytes;
            return Poll::Ready(Some(Ok(queued.response)));
        }
        if let Some(error) = state.terminal.take() {
            return Poll::Ready(Some(Err(error)));
        }
        if state.ended {
            return Poll::Ready(None);
        }

        if !state.waker.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
            state.waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}

impl fmt::Debug for Responses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Responses")
    }
}

impl Drop for Responses {
    fn drop(&mut self) {
        let mut state =
            self.shared.lock().expect("response state is not poisoned");
        state.detached = true;
        state.queue.clear();
        state.bytes = 0;
        state.waker = None;
    }
}

/// The stream state shared by [`Responses`] and the driver's [`Delivery`].
struct State {
    queue: VecDeque<Queued>,
    /// Encoded bytes in `queue`, checked against `limits.bytes`.
    bytes: usize,
    terminal: Option<Error>,
    ended: bool,
    /// Set when the consumer drops [`Responses`]. Later deliveries are
    /// discarded without taking budget.
    detached: bool,
    waker: Option<Waker>,
    budget: Budget,
    limits: WriteLimits,
    /// The `max_client_handles` slot, shared with [`ClientTransactionId`].
    _handle: Arc<Permit>,
}

/// An unread response and its share of the endpoint-wide budget.
struct Queued {
    response: Response<Bytes>,
    _permit: Permit,
    bytes: usize,
}

/// The driver's side of a response stream.
pub(super) struct Delivery(Arc<Mutex<State>>);

impl Delivery {
    /// Ends the stream without an error, as Timer M does for an INVITE that
    /// received a 2xx.
    pub(super) fn end(self) {
        self.update(|state| state.ended = true);
    }

    pub(super) fn observation(&self) -> Observation {
        Observation(Arc::downgrade(&self.0))
    }

    pub(super) fn response(&self, response: Response<Bytes>) {
        self.update(|state| {
            if state.ended || state.detached {
                return;
            }

            let bytes = response.encoded_len().unwrap_or(usize::MAX);
            let permit = if state.queue.len() < state.limits.messages
                && bytes <= state.limits.bytes.saturating_sub(state.bytes)
            {
                state.budget.acquire(bytes)
            } else {
                None
            };
            if let Some(permit) = permit {
                state.bytes += bytes;
                state.queue.push_back(Queued {
                    response,
                    _permit: permit,
                    bytes,
                });
            } else {
                state.terminal = Some(Error::delivery_overflow());
                state.ended = true;
            }
        });
    }

    pub(super) fn send(self, result: Result<Response<Bytes>, Error>) {
        match result {
            Ok(response) => self.response(response),
            Err(error) => self.update(|state| {
                if !state.ended && !state.detached {
                    state.terminal = Some(error);
                }
            }),
        }
        self.update(|state| state.ended = true);
    }

    fn update(&self, update: impl FnOnce(&mut State)) {
        let wake = {
            let mut state =
                self.0.lock().expect("response state is not poisoned");
            update(&mut state);
            state.waker.take()
        };
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        self.update(|state| {
            if !state.ended && !state.detached {
                state.terminal = Some(Error::closed());
                state.ended = true;
            }
        });
    }
}

/// A weak identity of a [`Delivery`]. A write receipt that completes after
/// its transaction ended cannot match the delivery of a reused table slot.
pub(super) struct Observation(Weak<Mutex<State>>);

impl Observation {
    pub(super) fn matches(&self, delivery: &Delivery) -> bool {
        self.0.ptr_eq(&Arc::downgrade(&delivery.0))
    }
}

/// A queued start. The driver answers it with a rejection, or splits it into
/// the transaction handles once it installs the machine.
pub(super) struct Starting {
    accepted: oneshot::Sender<Result<ClientTransaction, Error>>,
    observation: Observing,
    /// What an INVITE reserved for its CANCEL.
    cancel: Option<Reserved>,
}

/// The handles of a transaction before the driver installs it.
pub(super) struct Observing {
    commands: mpsc::UnboundedSender<Command>,
    responses: Responses,
}

/// The admission and observation capacity an admitted INVITE holds for one
/// CANCEL transaction.
pub(super) struct Reserved {
    pub(super) permit: admission::Permit,
    pub(super) observation: Observing,
}

impl Starting {
    pub(super) fn send(self, result: Result<ClientTransaction, Error>) {
        let _ = self.accepted.send(result);
    }

    /// Splits the start into the channel that answers it, its handles, and
    /// the CANCEL reservation of an INVITE.
    pub(super) fn split(
        self,
    ) -> (
        oneshot::Sender<Result<ClientTransaction, Error>>,
        Observing,
        Option<Reserved>,
    ) {
        (self.accepted, self.observation, self.cancel)
    }
}

impl Observing {
    pub(super) fn new(
        commands: mpsc::UnboundedSender<Command>,
        responses: Responses,
    ) -> Observing {
        Observing { commands, responses }
    }

    /// The driver's side of the response stream.
    pub(super) fn delivery(&self) -> Delivery {
        Delivery(self.responses.shared.clone())
    }

    /// The caller's transaction once the driver has installed it. `cancel`
    /// is set for an INVITE.
    pub(super) fn finish(
        self,
        via: HeaderValue,
        flow: Flow,
        cancel: Option<CancelHandle>,
    ) -> ClientTransaction {
        let handle = self
            .responses
            .shared
            .lock()
            .expect("response state is not poisoned")
            ._handle
            .clone();

        ClientTransaction {
            control: ClientControl {
                id: ClientTransactionId(handle),
                via,
                flow,
                cancel,
                commands: self.commands,
            },
            responses: self.responses,
        }
    }
}

impl Endpoint {
    /// Starts an INVITE or non-INVITE client transaction toward `target`.
    ///
    /// The driver prepares the transport, prepends a Via with a fresh branch
    /// and sends the request. The future returns after driver acceptance, and
    /// [`ClientControl::flow`] then has the actual local address. After
    /// acceptance, failures belong to [`Responses`], including ones that occur
    /// before this future resumes. See [RFC 3261 section 17].
    ///
    /// # INVITE
    ///
    /// An INVITE needs one From and one To with a valid URI, one Call-ID, and
    /// a CSeq below 2<sup>31</sup> ([RFC 3261 section 8.1.1.5]), since its
    /// ACK and CANCEL copy them. The transaction keeps those values, the
    /// Request-URI, the Route values, its top Via and the next hop until the
    /// final response, without the body or the buffer they came in.
    ///
    /// Retransmissions stop at the first provisional response, and nothing
    /// times the INVITE out after that. Timer B ends only an INVITE that got
    /// no response at all. The TU applies its own limit on ringing, such as a
    /// proxy's Timer C, and calls [`ClientControl::cancel`].
    ///
    /// The transaction acknowledges a non-2xx final response itself, on the
    /// INVITE's next hop, and again for each retransmission of that response
    /// ([RFC 3261 section 17.1.1.3]). The TU acknowledges each 2xx
    /// ([RFC 3261 section 13.2.2.4]). See [`Responses`].
    ///
    /// Admission reserves a CANCEL transaction with each INVITE, in
    /// [`Builder::max_client_transactions`] and
    /// [`Builder::max_client_handles`], so a cancellation never waits for
    /// capacity.
    ///
    /// # Routing
    ///
    /// The request is one the caller has already routed, and `target` is its
    /// next hop. This is the split of [RFC 3261 section 17.1], where the TU
    /// hands a client transaction the request together with the address, port
    /// and transport to send it to. `start` does not pick a hop from the
    /// Request-URI or Route, apply strict or loose routing, resolve a URI as
    /// [RFC 3263 section 4] does, or check that `target` matches either URI.
    /// The Request-URI and Route rows go out as given.
    ///
    /// Plaintext never satisfies SIPS, but the only SIPS check here is on the
    /// scheme of the Request-URI. A `sips:` Request-URI, in any letter case,
    /// is refused before admission. [RFC 3261 section 8.1.2] requires TLS for
    /// it whichever URI the next hop came from, and signa sends over UDP and
    /// TCP only. A `sip:` Request-URI does not make plaintext acceptable,
    /// though. A `sips:` route can require TLS too ([RFC 5630 section 5.1.1]),
    /// and a built request does not say which entry is the next hop. With a
    /// strict router first in the route set, that hop is the Request-URI, and
    /// the top Route may still carry `lr` ([RFC 3261 section 12.2.1.1]).
    ///
    /// So the caller chooses a target and transport that meet the security
    /// requirements of its routing, and does not use this endpoint for a
    /// request that needs TLS. Accepting a request does not mean that its
    /// Route, its target, or its SIPS requirements were checked.
    ///
    /// # TCP
    ///
    /// The `sent-by` of the Via is the connection's local address with the
    /// port of the endpoint's TCP listener, when [`Builder::tcp`] has one that
    /// accepts connections on that address. A server whose connection has
    /// closed can then answer on a new connection, so a closed connection does
    /// not end the transaction. Timer F ends a non-INVITE without a final
    /// response, and Timer B an INVITE without any. Without such a listener
    /// the Via names the connection's own port, and the transaction fails
    /// with a transport error as soon as the connection closes, since no
    /// response can reach it any more.
    ///
    /// # Cancellation
    ///
    /// Dropping an unpolled future does nothing. The first poll queues the
    /// operation, and a queued operation may execute even if this future is
    /// dropped. A caller that drops it before it resolves cannot tell whether
    /// the request was sent. Starting the request again sends a second
    /// transaction with a new branch, so do not retry blindly. An INVITE whose
    /// future was dropped runs without anyone to observe or cancel it, so a
    /// 2xx to it goes unacknowledged. Dropping the future is never a CANCEL.
    ///
    /// # Errors
    ///
    /// * [`Error::is_missing_header`] for a request without CSeq, or an INVITE
    ///   without From, To or Call-ID.
    /// * [`Error::is_invalid_cseq`] unless the request's CSeq is one parseable
    ///   value with its own method, below 2<sup>31</sup> for an INVITE.
    /// * [`Error::is_invalid_header`] for an INVITE with more than one From,
    ///   To or Call-ID, or one that does not parse.
    /// * [`Error::is_unsupported_method`] for ACK and CANCEL. An ACK for a 2xx
    ///   goes through [`Endpoint::send_request`], and an INVITE's CANCEL
    ///   through [`ClientControl::cancel`]. Extension methods are supported.
    /// * [`Error::is_unsupported_routing`] for a `sips:` Request-URI, a
    ///   multicast target, or a UDP target on an endpoint without a UDP
    ///   socket. Route is not checked, as Routing above explains.
    /// * [`Error::is_too_large`] for a UDP request over 1300 bytes.
    /// * [`Error::is_busy`] when client admission, handle capacity or
    ///   transport output is full.
    /// * [`Error::is_transport`] when the transport cannot be prepared.
    /// * [`Error::is_closed`] once the endpoint has stopped or started to
    ///   shut down.
    ///
    /// # Example
    ///
    /// An OPTIONS to a next hop the caller has already picked. The stream
    /// yields provisional responses, then the final one or a terminal error.
    ///
    /// ```
    /// use std::error::Error;
    ///
    /// use bytes::Bytes;
    /// use signa::{
    ///     endpoint::{Endpoint, Target},
    ///     transport::Transport,
    ///     Request,
    /// };
    ///
    /// async fn ping(endpoint: &Endpoint) -> Result<(), Box<dyn Error>> {
    ///     let next_hop = "192.0.2.4:5060".parse()?;
    ///     let target = Target::new(Transport::Udp, next_hop);
    ///     let request = Request::builder()
    ///         .method("OPTIONS")
    ///         .uri("sip:bob@192.0.2.4")
    ///         .header("From", "<sip:alice@192.0.2.1>;tag=1928301774")
    ///         .header("To", "<sip:bob@192.0.2.4>")
    ///         .header("Call-ID", "a84b4c76e66710")
    ///         .header("CSeq", "1 OPTIONS")
    ///         .header("Max-Forwards", "70")
    ///         .body(Bytes::new())?;
    ///
    ///     let (control, mut responses) =
    ///         endpoint.start(request, target).await?.into_parts();
    ///     println!("sent from {}", control.flow().local);
    ///     while let Some(response) = responses.next().await {
    ///         println!("{}", response?.status());
    ///     }
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [RFC 3261 section 17]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17
    /// [RFC 3261 section 17.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1
    /// [RFC 3263 section 4]: https://www.rfc-editor.org/rfc/rfc3263.html#section-4
    /// [RFC 3261 section 8.1.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.2
    /// [RFC 5630 section 5.1.1]: https://www.rfc-editor.org/rfc/rfc5630.html#section-5.1.1
    /// [RFC 3261 section 12.2.1.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-12.2.1.1
    /// [RFC 3261 section 8.1.1.5]: https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.5
    /// [RFC 3261 section 17.1.1.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.3
    /// [RFC 3261 section 13.2.2.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4
    /// [RFC 3261 section 18.1.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.1.1
    /// [`Builder::tcp`]: super::Builder::tcp
    /// [`Builder::max_client_transactions`]: super::Builder::max_client_transactions
    /// [`Builder::max_client_handles`]: super::Builder::max_client_handles
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn start(
        &self,
        request: Request<Bytes>,
        target: Target,
    ) -> impl Future<Output = Result<ClientTransaction, Error>> + Send + '_
    {
        async move {
            let response = self.enqueue(request, target)?;
            response.await.unwrap_or_else(|_| Err(Error::closed()))
        }
    }

    fn enqueue(
        &self,
        request: Request<Bytes>,
        target: Target,
    ) -> Result<oneshot::Receiver<Result<ClientTransaction, Error>>, Error>
    {
        if self.reception == Reception::Stateless {
            return Err(Error::unsupported_reception());
        }
        if self.commands.is_closed() {
            return Err(Error::closed());
        }
        validate(&request)?;
        if target.address.ip().is_multicast()
            || (target.transport == Transport::Udp && self.udp.is_none())
        {
            return Err(Error::unsupported_routing());
        }

        let (permit, cancel) = if request.method() == Method::INVITE {
            let (permit, cancel) =
                self.client_admission.acquire_invite(&request)?;
            (permit, Some(cancel))
        } else {
            (self.client_admission.acquire(&request)?, None)
        };
        let observation = self.observing()?;
        let cancel = match cancel {
            Some(permit) => {
                Some(Reserved { permit, observation: self.observing()? })
            }
            None => None,
        };

        let (accepted, response) = oneshot::channel();
        self.commands
            .send(Command::Send {
                request,
                transport: target.transport,
                next_hop: target.address,
                respond: Starting { accepted, observation, cancel },
                permit,
            })
            .map_err(|_| Error::closed())?;
        Ok(response)
    }

    /// Reserves one `max_client_handles` slot for a response stream.
    fn observing(&self) -> Result<Observing, Error> {
        let handle = self.client_handles.acquire(0).ok_or_else(Error::busy)?;
        let responses = Responses::new(
            self.client_response_budget.clone(),
            self.client_response_limits,
            handle,
        );
        Ok(Observing::new(self.commands.clone(), responses))
    }
}

/// Checks the request before `start` reserves any capacity.
fn validate(request: &Request<Bytes>) -> Result<(), Error> {
    // The current transports cannot satisfy the TLS that a SIPS Request-URI
    // requires. This is the only SIPS check. Route and the target are the
    // caller's, as the routing section of `Endpoint::start` says.
    if request
        .uri()
        .as_str()
        .get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("sips:"))
    {
        return Err(Error::unsupported_routing());
    }
    if matches!(*request.method(), Method::ACK | Method::CANCEL) {
        return Err(Error::unsupported_method());
    }

    let mut values = request.headers().get_all(CSEQ);
    let value = values.next().ok_or_else(|| Error::missing(CSEQ))?;
    let cseq = CSeq::parse(value)
        .filter(|cseq| cseq.method == request.method())
        .filter(|_| values.next().is_none())
        .ok_or_else(Error::invalid_cseq)?;

    if request.method() == Method::INVITE {
        // RFC 3261 section 8.1.1.5. The ACK and CANCEL repeat the number.
        if cseq.number >= 1 << 31 {
            return Err(Error::invalid_cseq());
        }
        validate_identity(request)?;
    }
    Ok(())
}

/// Checks the From, To and Call-ID that an INVITE's ACK and CANCEL copy.
///
/// The transaction layer copies them verbatim, so it checks the structure it
/// relies on rather than full UA semantics. From and To are a `name-addr` or
/// `addr-spec`, whose URI has a valid SIP or SIPS structure or another
/// scheme. Call-ID is `word ["@" word]` (RFC 3261 section 25.1). A From tag is
/// not required, so a proxy can forward an INVITE from an RFC 2543 client.
fn validate_identity(request: &Request<Bytes>) -> Result<(), Error> {
    let one = |name: HeaderName| {
        let mut values = request.headers().get_all(&name);
        match (values.next(), values.next()) {
            (Some(value), None) => Ok(value.as_str()),
            (None, _) => Err(Error::missing(name)),
            (Some(_), Some(_)) => Err(Error::invalid_header(name)),
        }
    };

    // A SIP or SIPS URI gets its structure checked. Another scheme, such as
    // `tel:`, needs `scheme ":"` and what the message layer accepts after it.
    let valid_uri = |uri: &str| {
        let Ok(uri) = uri.parse::<Uri>() else { return false };
        match uri.sip() {
            Ok(Some(_)) => true,
            Ok(None) => {
                uri.as_str().split_once(':').is_some_and(|(scheme, rest)| {
                    !rest.is_empty()
                        && scheme
                            .bytes()
                            .next()
                            .is_some_and(|b| b.is_ascii_alphabetic())
                        && scheme.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || b"+-.".contains(&b)
                        })
                })
            }
            Err(_) => false,
        }
    };
    for name in [FROM, TO] {
        let value = one(name.clone())?;
        if !address::uri(value).is_some_and(valid_uri) {
            return Err(Error::invalid_header(name));
        }
    }

    let call_id = one(CALL_ID)?.trim();
    let word = |word: &str| {
        !word.is_empty()
            && word.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || b"-.!%*_+`'~()<>:\\\"/[]?{}".contains(&b)
            })
    };
    let valid = match call_id.split_once('@') {
        Some((local, host)) => word(local) && word(host),
        None => word(call_id),
    };
    if !valid {
        return Err(Error::invalid_header(CALL_ID));
    }
    Ok(())
}

// A final-response `Service` client for the driver and transport tests. It
// runs on the TU operations and is not public API. Only the socket tests use
// it, and Miri skips those.
#[cfg(all(test, not(miri)))]
pub(super) mod compatibility {
    use std::pin::Pin;

    use tokio::sync::mpsc;
    use tower_service::Service;

    use super::*;
    use crate::endpoint::admission::ClientAdmission;

    #[derive(Clone, Debug)]
    pub(in crate::endpoint) struct Client {
        commands: mpsc::UnboundedSender<Command>,
        admission: ClientAdmission,
        transport: Transport,
        next_hop: SocketAddr,
    }

    impl Client {
        pub(in crate::endpoint) fn new(
            commands: mpsc::UnboundedSender<Command>,
            admission: ClientAdmission,
            transport: Transport,
            next_hop: SocketAddr,
        ) -> Client {
            Client { commands, admission, transport, next_hop }
        }
    }

    impl Service<Request<Bytes>> for Client {
        type Response = Response<Bytes>;
        type Error = Error;
        type Future = ResponseFuture;

        /// Always ready. `call` reserves count and byte capacity without
        /// waiting, and returns a failed future when admission is full or
        /// closed.
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<Bytes>) -> ResponseFuture {
            if self.commands.is_closed() {
                return ResponseFuture::failed(Error::closed());
            }
            // The final-only adapter cannot cancel or acknowledge a 2xx, so
            // it refuses INVITE.
            if request.method() == Method::INVITE {
                return ResponseFuture::failed(Error::unsupported_method());
            }
            if let Err(error) = validate(&request) {
                return ResponseFuture::failed(error);
            }
            let permit = match self.admission.acquire(&request) {
                Ok(permit) => permit,
                Err(error) => return ResponseFuture::failed(error),
            };

            let (accepted, response) = oneshot::channel();
            let responses = Responses::new(
                Budget::new(WriteLimits {
                    messages: 4096,
                    bytes: 64 * 1024 * 1024,
                }),
                WriteLimits { messages: 64, bytes: 1024 * 1024 },
                Budget::new(WriteLimits { messages: 1, bytes: 1 })
                    .acquire(0)
                    .unwrap(),
            );
            let respond = Starting {
                accepted,
                observation: Observing::new(self.commands.clone(), responses),
                cancel: None,
            };
            let command = Command::Send {
                request,
                transport: self.transport,
                next_hop: self.next_hop,
                respond,
                permit,
            };
            let state = match self.commands.send(command) {
                Ok(()) => LegacyState::Waiting(Box::pin(async move {
                    let transaction =
                        response.await.map_err(|_| Error::closed())??;
                    let (control, mut responses) = transaction.into_parts();
                    drop(control);
                    while let Some(response) = responses.next().await {
                        let response = response?;
                        if response.status().as_u16() >= 200 {
                            return Ok(response);
                        }
                    }
                    Err(Error::closed())
                })),
                Err(_) => LegacyState::Failed(Some(Error::closed())),
            };

            ResponseFuture { state }
        }
    }

    pub(in crate::endpoint) struct ResponseFuture {
        state: LegacyState,
    }

    enum LegacyState {
        Waiting(
            Pin<
                Box<
                    dyn Future<Output = Result<Response<Bytes>, Error>> + Send,
                >,
            >,
        ),
        Failed(Option<Error>),
    }

    impl ResponseFuture {
        fn failed(error: Error) -> ResponseFuture {
            ResponseFuture { state: LegacyState::Failed(Some(error)) }
        }
    }

    impl fmt::Debug for ResponseFuture {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("ResponseFuture")
        }
    }

    impl Future for ResponseFuture {
        type Output = Result<Response<Bytes>, Error>;

        fn poll(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Self::Output> {
            match &mut self.state {
                LegacyState::Waiting(future) => future.as_mut().poll(cx),
                LegacyState::Failed(error) => {
                    Poll::Ready(Err(error.take().unwrap()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These stream tests need an executor but no I/O driver, including under
    // Miri.
    fn run(future: impl Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future);
    }

    fn stream(limits: WriteLimits, budget: Budget) -> (Delivery, Responses) {
        let handle = Budget::new(WriteLimits { messages: 1, bytes: 1 })
            .acquire(0)
            .unwrap();
        let responses = Responses::new(budget, limits, handle);
        (Delivery(responses.shared.clone()), responses)
    }

    fn response(status: u16) -> Response<Bytes> {
        Response::builder().status(status).body(Bytes::new()).unwrap()
    }

    fn budget() -> Budget {
        Budget::new(WriteLimits { messages: 10, bytes: 4096 })
    }

    #[test]
    fn overflow_preserves_queued_responses_and_reserved_terminal_error() {
        run(async {
            for limits in [
                WriteLimits { messages: 1, bytes: 4096 },
                WriteLimits {
                    messages: 10,
                    bytes: response(100).encoded_len().unwrap(),
                },
            ] {
                let (delivery, mut responses) = stream(limits, budget());

                delivery.response(response(100));
                delivery.response(response(200));
                delivery.send(Err(Error::timeout()));

                assert_eq!(
                    responses.next().await.unwrap().unwrap().status().as_u16(),
                    100
                );
                assert!(
                    responses
                        .next()
                        .await
                        .unwrap()
                        .unwrap_err()
                        .is_delivery_overflow()
                );
                assert!(responses.next().await.is_none());
                assert!(responses.next().await.is_none());
            }
        });
    }

    #[test]
    fn endpoint_budget_survives_machine_completion_until_consumption() {
        run(async {
            let budget = Budget::new(WriteLimits { messages: 1, bytes: 4096 });
            let limits = WriteLimits { messages: 10, bytes: 4096 };
            let (delivery, mut responses) = stream(limits, budget.clone());

            delivery.send(Ok(response(200)));
            assert!(budget.acquire(0).is_none());

            let (other, mut overflow) = stream(limits, budget.clone());
            other.send(Ok(response(200)));
            assert!(
                overflow
                    .next()
                    .await
                    .unwrap()
                    .unwrap_err()
                    .is_delivery_overflow()
            );

            assert!(responses.next().await.unwrap().is_ok());
            assert!(budget.is_idle());
        });
    }

    #[test]
    fn sender_drop_yields_closed_after_queued_response() {
        run(async {
            let (delivery, mut responses) =
                stream(WriteLimits { messages: 10, bytes: 4096 }, budget());
            {
                let mut receive = std::pin::pin!(responses.next());
                poll_fn(|cx| {
                    assert!(receive.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
            }

            delivery.response(response(100));
            drop(delivery);

            assert_eq!(
                responses.next().await.unwrap().unwrap().status().as_u16(),
                100
            );
            assert!(responses.next().await.unwrap().unwrap_err().is_closed());
            assert!(responses.next().await.is_none());
        });
    }

    #[test]
    fn detached_consumer_releases_bytes_without_affecting_delivery_owner() {
        let budget = budget();
        let (delivery, responses) =
            stream(WriteLimits { messages: 10, bytes: 4096 }, budget.clone());
        delivery.response(response(100));

        drop(responses);
        assert!(budget.is_idle());

        delivery.response(response(200));
        assert!(budget.is_idle());
    }

    // Equality and hashing use only the immutable allocation address.
    #[test]
    #[allow(clippy::mutable_key_type)]
    fn transaction_ids_keep_identity_and_reservation_after_control_drop() {
        let budget = Budget::new(WriteLimits { messages: 2, bytes: 1 });
        let first = ClientTransactionId(Arc::new(budget.acquire(0).unwrap()));
        let second = ClientTransactionId(Arc::new(budget.acquire(0).unwrap()));

        let mut ids = std::collections::HashSet::new();
        assert!(ids.insert(first.clone()));
        assert!(!ids.insert(first.clone()));
        assert!(ids.insert(second.clone()));

        drop(first);
        drop(second);
        assert!(budget.acquire(0).is_none());
        drop(ids);
        assert!(budget.is_idle());
    }

    #[test]
    fn response_limits_and_handle_capacity_must_be_positive() {
        for builder in [
            Endpoint::builder().max_client_handles(0),
            Endpoint::builder()
                .client_response_limits(WriteLimits { messages: 0, bytes: 1 }),
            Endpoint::builder()
                .client_response_limits(WriteLimits { messages: 1, bytes: 0 }),
            Endpoint::builder()
                .client_response_budget(WriteLimits { messages: 0, bytes: 1 }),
            Endpoint::builder()
                .client_response_budget(WriteLimits { messages: 1, bytes: 0 }),
        ] {
            assert!(builder.bind().unwrap_err().is_invalid_config());
        }
    }

    fn invite() -> Request<Bytes> {
        Request::builder()
            .method("INVITE")
            .uri("sip:bob@example.com")
            .header("From", "Alice <sip:alice@example.com>;tag=1")
            .header("To", "<sip:bob@example.com>")
            .header("Call-ID", "a84b4c76e66710@pc33.example.com")
            .header("CSeq", "2147483647 INVITE")
            .body(Bytes::new())
            .unwrap()
    }

    // RFC 3261 sections 8.1.1.5, 9.1 and 17.1.1.3. The ACK and CANCEL copy
    // these fields, so an INVITE without a usable copy is never sent.
    #[test]
    fn invite_identity_is_validated_before_admission() {
        assert!(validate(&invite()).is_ok());

        for (name, value) in [
            ("From", "\"Alice\" <sip:alice@example.com>"),
            ("From", "sip:alice@example.com;tag=1"),
            ("To", "Bob <tel:+12015550123>;tag=x"),
            ("Call-ID", "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"),
            ("Call-ID", "a!%*_+`'~()<>:\\\"/[]?{}@[2001:db8::1]"),
        ] {
            let mut request = invite();
            request
                .headers_mut()
                .insert(name.parse().unwrap(), value.parse().unwrap());
            assert!(validate(&request).is_ok(), "{name}: {value}");
        }

        // A missing header has a predicate of its own, apart from a duplicated
        // or malformed one.
        for name in [CSEQ, FROM, TO, CALL_ID] {
            let mut request = invite();
            request.headers_mut().remove(&name);
            let error = validate(&request).unwrap_err();
            assert!(error.is_missing_header(), "{name}: {error}");
            assert!(!error.is_invalid_cseq() && !error.is_invalid_header());
            assert_eq!(
                error.to_string(),
                format!("the request has no {name}")
            );
        }

        for name in [FROM, TO, CALL_ID] {
            let mut request = invite();
            let value = request.headers().get(&name).unwrap().clone();
            request.headers_mut().append(name.clone(), value);
            assert!(validate(&request).unwrap_err().is_invalid_header());
        }

        for (name, value) in [
            ("From", "<sip:alice@example.com"),
            ("From", "Alice"),
            ("To", "<not a uri>"),
            ("To", "<bob@example.com>"),
            ("To", "<sip:>"),
            ("To", "\"Bob <sip:bob@example.com>"),
            ("Call-ID", "two words"),
            ("Call-ID", "a@b@c"),
            ("Call-ID", "@example.com"),
            ("Call-ID", "caf\u{e9}"),
        ] {
            let mut request = invite();
            request
                .headers_mut()
                .insert(name.parse().unwrap(), value.parse().unwrap());
            assert!(
                validate(&request).unwrap_err().is_invalid_header(),
                "{name}: {value}"
            );
        }

        for cseq in ["2147483648 INVITE", "4294967295 INVITE", "1 OPTIONS"] {
            let mut request = invite();
            request.headers_mut().insert(CSEQ, cseq.parse().unwrap());
            assert!(validate(&request).unwrap_err().is_invalid_cseq());
        }
    }

    fn routed(uri: &str, routes: &[&str]) -> Request<Bytes> {
        let mut builder = Request::builder()
            .method("OPTIONS")
            .uri(uri)
            .header("CSeq", "1 OPTIONS");
        for route in routes {
            builder = builder.header("Route", *route);
        }
        builder.body(Bytes::new()).unwrap()
    }

    // RFC 3261 section 8.1.2. A SIPS Request-URI needs TLS whichever URI
    // the next hop came from, so a `sip:` Route does not change the answer.
    #[test]
    fn plaintext_transports_cannot_submit_sips_request_uris() {
        for uri in
            ["sips:alice@example.com", "SIPS:alice@example.com", "SiPs:alice"]
        {
            for routes in [&[][..], &["<sip:proxy.example.net;lr>"]] {
                let request = routed(uri, routes);
                assert!(
                    validate(&request).unwrap_err().is_unsupported_routing(),
                    "{uri} {routes:?}"
                );
            }
        }
    }

    // signa's boundary, not an RFC rule. The caller owns routing and the
    // security it requires, so `validate` does not read Route. Passing here
    // does not make plaintext right for these requests. RFC 5630 section
    // 5.1.1 requires TLS for a `sips:` loose route, which a caller of this
    // endpoint cannot provide.
    #[test]
    fn sips_routes_are_left_to_the_caller() {
        for routes in [
            &["<sips:proxy.example.net;lr>"][..],
            &["<sips:strict.example.net>"],
            &["<SIPS:proxy.example.net;lr>"],
            &["<sip:proxy.example.net;lr>, <sips:edge.example.net;lr>"],
            &["<sip:proxy.example.net;lr>", "<sips:edge.example.net;lr>"],
            &["<sips:a.example.net;lr>", "<sips:b.example.net;lr>"],
        ] {
            let request = routed("sip:alice@example.com", routes);
            assert!(validate(&request).is_ok(), "{routes:?}");
        }
    }

    #[test]
    fn validates_cseq_and_method_before_admission() {
        for value in [
            "",
            "1",
            "1 BYE",
            "1 options",
            "-1 OPTIONS",
            "4294967296 OPTIONS",
            "1 OPTIONS extra",
            "1 OPTIONS, 2 OPTIONS",
        ] {
            let request = Request::builder()
                .method("OPTIONS")
                .uri("sip:example.com")
                .header("CSeq", value)
                .body(Bytes::new())
                .unwrap();
            assert!(validate(&request).unwrap_err().is_invalid_cseq());
        }

        for method in ["ACK", "CANCEL"] {
            let request = Request::builder()
                .method(method)
                .uri("sip:example.com")
                .header("CSeq", format!("1 {method}").as_str())
                .body(Bytes::new())
                .unwrap();
            assert!(validate(&request).unwrap_err().is_unsupported_method());
        }

        for method in ["OPTIONS", "X-VENDOR", "invite", "ack", "cancel"] {
            let mut request = Request::builder()
                .method(method)
                .uri("sip:example.com")
                .header("CSeq", format!(" 007\r\n {method} \t").as_str())
                .body(Bytes::new())
                .unwrap();
            assert!(validate(&request).is_ok());

            request.headers_mut().append(CSEQ, "1 OPTIONS".parse().unwrap());
            assert!(validate(&request).unwrap_err().is_invalid_cseq());
            request.headers_mut().remove(CSEQ);
            assert!(validate(&request).is_err());
        }
    }
}
