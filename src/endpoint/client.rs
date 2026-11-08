/*!
Client transaction submission and bounded response observation.
*/

use std::{
    collections::VecDeque,
    fmt,
    future::{poll_fn, Future},
    hash::{Hash, Hasher},
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use super::{driver::Command, Endpoint, Error};
use crate::{
    message::{
        header::{cseq::CSeq, HeaderValue, CSEQ},
        request::Request,
        response::Response,
        Method,
    },
    transport::{
        budget::{Budget, Permit},
        Flow, Transport, WriteLimits,
    },
};

/// An explicit next-hop address and transport. URI routing belongs to the TU.
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

/// Metadata for an accepted transaction.
///
/// Dropping it does not stop the machine. INVITE cancellation is added with
/// INVITE endpoint support.
#[derive(Debug)]
pub struct ClientControl {
    id: ClientTransactionId,
    via: HeaderValue,
    flow: Flow,
    _commands: mpsc::UnboundedSender<Command>,
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
}

/// Responses accepted by the transaction machine, in arrival order.
///
/// Every accepted provisional response is observable. A non-INVITE final ends
/// observation even while Timer K keeps the machine alive. See
/// [RFC 3261 section 17.1.2].
///
/// # Overflow
///
/// Each stream is bounded by [`Builder::client_response_limits`] and shares
/// [`Builder::client_response_budget`] with the others. Overflow preserves
/// queued responses and then yields one explicit error.
///
/// # Cancellation
///
/// Receiving is cancellation-safe and fused. Dropping observation never
/// cancels SIP work.
///
/// [RFC 3261 section 17.1.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.2
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
    commands: mpsc::UnboundedSender<Command>,
    responses: Responses,
}

impl Starting {
    pub(super) fn send(self, result: Result<ClientTransaction, Error>) {
        let _ = self.accepted.send(result);
    }

    /// Returns the driver's delivery, the caller's transaction, and the
    /// channel that hands the transaction over.
    pub(super) fn prepare(
        self,
        via: HeaderValue,
        flow: Flow,
    ) -> (
        Delivery,
        ClientTransaction,
        oneshot::Sender<Result<ClientTransaction, Error>>,
    ) {
        let delivery = Delivery(self.responses.shared.clone());
        let handle = self
            .responses
            .shared
            .lock()
            .expect("response state is not poisoned")
            ._handle
            .clone();
        let transaction = ClientTransaction {
            control: ClientControl {
                id: ClientTransactionId(handle),
                via,
                flow,
                _commands: self.commands,
            },
            responses: self.responses,
        };

        (delivery, transaction, self.accepted)
    }
}

impl Endpoint {
    /// Starts a non-INVITE client transaction toward `target`.
    ///
    /// The driver prepares the transport, prepends a Via with a fresh branch
    /// and sends the request. The future returns after driver acceptance, and
    /// [`ClientControl::flow`] then has the actual local address. After
    /// acceptance, failures belong to [`Responses`], including ones that occur
    /// before this future resumes. See [RFC 3261 section 17].
    ///
    /// # TCP
    ///
    /// The `sent-by` of the Via is the connection's local address with the
    /// port of the endpoint's TCP listener, when [`Builder::tcp`] has one that
    /// accepts connections on that address. A server whose connection has
    /// closed can then answer on a new connection, so a closed connection does
    /// not end the transaction, and Timer F does if no final arrives. Without
    /// such a listener the Via names the connection's own port, and the
    /// transaction fails with a transport error as soon as the connection
    /// closes, since no response can reach it any more.
    ///
    /// # Cancellation
    ///
    /// Dropping an unpolled future does nothing. The first poll queues the
    /// operation, and a queued operation may execute even if this future is
    /// dropped. A caller that drops it before it resolves cannot tell whether
    /// the request was sent. Starting the request again sends a second
    /// transaction with a new branch, so do not retry blindly.
    ///
    /// # Errors
    ///
    /// * [`Error::is_invalid_cseq`] unless the request has one parseable CSeq
    ///   with its own method. A request without CSeq gets an error naming it.
    /// * [`Error::is_unsupported_method`] for INVITE, ACK and CANCEL. ACK and
    ///   CANCEL need explicit protocol operations, and INVITE waits for its
    ///   endpoint machine. Extension methods are supported.
    /// * [`Error::is_unsupported_routing`] for a SIPS request, a multicast
    ///   target, or a UDP target on an endpoint without a UDP socket.
    /// * [`Error::is_too_large`] for a UDP request over 1300 bytes.
    /// * [`Error::is_busy`] when client admission, handle capacity or
    ///   transport output is full.
    /// * [`Error::is_transport`] when the transport cannot be prepared.
    /// * [`Error::is_closed`] once the endpoint has stopped or started to
    ///   shut down.
    ///
    /// [RFC 3261 section 17]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17
    /// [`Builder::tcp`]: super::Builder::tcp
    #[allow(clippy::manual_async_fn)] // Expose the Send guarantee on Rust 1.71.
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
        if self.commands.is_closed() {
            return Err(Error::closed());
        }
        validate(&request)?;
        if target.address.ip().is_multicast()
            || (target.transport == Transport::Udp && self.udp.is_none())
        {
            return Err(Error::unsupported_routing());
        }

        let permit = self.client_admission.acquire(&request)?;
        let handle = self.client_handles.acquire(0).ok_or_else(Error::busy)?;
        let responses = Responses::new(
            self.client_response_budget.clone(),
            self.client_response_limits,
            handle,
        );

        let (accepted, response) = oneshot::channel();
        self.commands
            .send(Command::Send {
                request,
                transport: target.transport,
                next_hop: target.address,
                respond: Starting {
                    accepted,
                    commands: self.commands.clone(),
                    responses,
                },
                permit,
            })
            .map_err(|_| Error::closed())?;
        Ok(response)
    }
}

/// Checks the request before `start` reserves any capacity.
fn validate(request: &Request<Bytes>) -> Result<(), Error> {
    // The current transports cannot satisfy a SIPS request's TLS requirement.
    if request
        .uri()
        .as_str()
        .get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("sips:"))
    {
        return Err(Error::unsupported_routing());
    }
    if matches!(
        *request.method(),
        Method::INVITE | Method::ACK | Method::CANCEL
    ) {
        return Err(Error::unsupported_method());
    }

    let mut values = request.headers().get_all(CSEQ);
    let value = values.next().ok_or_else(|| Error::missing(CSEQ))?;
    if values.next().is_some()
        || !CSeq::parse(value)
            .is_some_and(|cseq| cseq.method == request.method())
    {
        return Err(Error::invalid_cseq());
    }
    Ok(())
}

// The final-response `Service` client that driver and transport tests were
// written against. It runs on the TU operations and is not public API. Only
// the socket tests use it, and Miri skips those.
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
                commands: self.commands.clone(),
                responses,
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
                assert!(responses
                    .next()
                    .await
                    .unwrap()
                    .unwrap_err()
                    .is_delivery_overflow());
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
            assert!(overflow
                .next()
                .await
                .unwrap()
                .unwrap_err()
                .is_delivery_overflow());

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

    #[test]
    fn plaintext_transports_cannot_submit_sips_requests() {
        for uri in ["sips:alice@example.com", "SIPS:alice@example.com"] {
            let request = Request::builder()
                .method("OPTIONS")
                .uri(uri)
                .header("CSeq", "1 OPTIONS")
                .body(Bytes::new())
                .unwrap();
            assert!(validate(&request).unwrap_err().is_unsupported_routing());
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

        for method in ["INVITE", "ACK", "CANCEL"] {
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
