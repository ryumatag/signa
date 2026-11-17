/*!
The adapter, as an external crate would write it.
*/

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use signa_core::{
    Request, Response,
    endpoint::{
        ReplyRoute, Responder, ResponseSubmission, ServerEvents,
        ServerRequest, ServerTransactionId, SubmitError,
    },
    transport::Flow,
};
use tower::{Layer, Service};

/// The handler envelope. It is the adapter's, not signa's, and holds what the
/// dispatcher took out of signa's `ServerRequest`.
pub(crate) struct Exchange<R> {
    pub(crate) request: Request<Bytes>,
    pub(crate) flow: Flow,
    pub(crate) transaction_id: ServerTransactionId,
    pub(crate) responder: R,
    pub(crate) events: ServerEvents,
    pub(crate) reply_route: ReplyRoute,
}

impl Exchange<Responder> {
    pub(crate) fn new(request: ServerRequest) -> Exchange<Responder> {
        let ServerRequest { request, received, transaction } = request;
        let flow = received.flow();
        let transaction_id = transaction.id();
        let (responder, events) = transaction.into_parts();
        // The route is cloned before the responder is wrapped, so no wrapper
        // needs to expose it.
        let reply_route = responder.reply_route();
        Exchange {
            request,
            flow,
            transaction_id,
            responder,
            events,
            reply_route,
        }
    }
}

impl<R> Exchange<R> {
    /// Replaces the response sender and keeps every other field.
    pub(crate) fn map_responder<T>(
        self,
        f: impl FnOnce(R) -> T,
    ) -> Exchange<T> {
        Exchange {
            request: self.request,
            flow: self.flow,
            transaction_id: self.transaction_id,
            responder: f(self.responder),
            events: self.events,
            reply_route: self.reply_route,
        }
    }
}

/// Sends responses for one server transaction.
///
/// The submission future is `Unpin`, which signa's `ResponseSubmission` is,
/// so a wrapper can poll the future it wraps without pin projection.
pub(crate) trait Respond {
    type Submission<'a>: Future<Output = Result<(), SubmitError>>
        + Send
        + Unpin
    where
        Self: 'a;

    fn respond(&self, response: Response<Bytes>) -> Self::Submission<'_>;
}

impl Respond for Responder {
    type Submission<'a> = ResponseSubmission<'a>;

    fn respond(&self, response: Response<Bytes>) -> ResponseSubmission<'_> {
        Responder::respond(self, response)
    }
}

/// What an observer saw of one submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    /// The driver accepted it. That is not delivery to the peer.
    Accepted,
    /// The driver or the responder refused it.
    Refused(SubmitError),
    /// The submission future was dropped before its result. It may still
    /// have been accepted.
    Interrupted,
}

/// The status and outcome of each observed submission, in order.
#[derive(Clone, Default)]
pub(crate) struct Log(Arc<Mutex<Vec<(u16, Outcome)>>>);

impl Log {
    fn push(&self, status: u16, outcome: Outcome) {
        self.0.lock().unwrap().push((status, outcome));
    }

    pub(crate) fn entries(&self) -> Vec<(u16, Outcome)> {
        self.0.lock().unwrap().clone()
    }
}

/// A sender that records each submission and its outcome.
pub(crate) struct Observed<R> {
    inner: R,
    log: Log,
}

impl<R: Respond> Respond for Observed<R> {
    type Submission<'a>
        = Observing<R::Submission<'a>>
    where
        Observed<R>: 'a;

    fn respond(
        &self,
        response: Response<Bytes>,
    ) -> Observing<R::Submission<'_>> {
        let status = response.status().as_u16();
        Observing {
            inner: self.inner.respond(response),
            pending: Some((status, self.log.clone())),
        }
    }
}

/// The named future of an observed submission.
pub(crate) struct Observing<F> {
    inner: F,
    pending: Option<(u16, Log)>,
}

impl<F> Future for Observing<F>
where
    F: Future<Output = Result<(), SubmitError>> + Unpin,
{
    type Output = Result<(), SubmitError>;

    fn poll(
        mut self: Pin<&mut Observing<F>>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), SubmitError>> {
        let result = ready!(Pin::new(&mut self.inner).poll(cx));
        if let Some((status, log)) = self.pending.take() {
            let outcome = match result {
                Ok(()) => Outcome::Accepted,
                Err(error) => Outcome::Refused(error),
            };
            log.push(status, outcome);
        }
        Poll::Ready(result)
    }
}

impl<F> Drop for Observing<F> {
    fn drop(&mut self) {
        if let Some((status, log)) = self.pending.take() {
            log.push(status, Outcome::Interrupted);
        }
    }
}

/// A second sender wrapper, to show that wrappers nest.
pub(crate) struct Counted<R> {
    inner: R,
    count: Arc<AtomicUsize>,
}

impl<R: Respond> Respond for Counted<R> {
    type Submission<'a>
        = R::Submission<'a>
    where
        Counted<R>: 'a;

    fn respond(&self, response: Response<Bytes>) -> R::Submission<'_> {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.inner.respond(response)
    }
}

/// Wraps the sender of every exchange in `Observed`.
#[derive(Clone)]
pub(crate) struct ObserveLayer(pub(crate) Log);

impl<S> Layer<S> for ObserveLayer {
    type Service = Observe<S>;

    fn layer(&self, inner: S) -> Observe<S> {
        Observe { inner, log: self.0.clone() }
    }
}

/// The service of `ObserveLayer`.
pub(crate) struct Observe<S> {
    inner: S,
    log: Log,
}

impl<S, R> Service<Exchange<R>> for Observe<S>
where
    R: Respond,
    S: Service<Exchange<Observed<R>>, Response = ()>,
{
    type Response = ();
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, exchange: Exchange<R>) -> S::Future {
        let log = self.log.clone();
        self.inner
            .call(exchange.map_responder(|inner| Observed { inner, log }))
    }
}

/// Wraps the sender of every exchange in `Counted`.
#[derive(Clone)]
pub(crate) struct CountLayer(pub(crate) Arc<AtomicUsize>);

impl<S> Layer<S> for CountLayer {
    type Service = Count<S>;

    fn layer(&self, inner: S) -> Count<S> {
        Count { inner, count: self.0.clone() }
    }
}

/// The service of `CountLayer`.
pub(crate) struct Count<S> {
    inner: S,
    count: Arc<AtomicUsize>,
}

impl<S, R> Service<Exchange<R>> for Count<S>
where
    R: Respond,
    S: Service<Exchange<Counted<R>>, Response = ()>,
{
    type Response = ();
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, exchange: Exchange<R>) -> S::Future {
        let count = self.count.clone();
        self.inner
            .call(exchange.map_responder(|inner| Counted { inner, count }))
    }
}
