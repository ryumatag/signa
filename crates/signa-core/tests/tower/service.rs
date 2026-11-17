/*!
The application: a leaf handler, its control service, and their shared call
state.
*/

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    future::{Future, pending},
    mem,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use signa_core::{
    endpoint::{Responder, ServerEvents, ServerTransactionId},
    message::header::{CALL_ID, Tag},
};
use tokio::{
    sync::{Notify, mpsc, oneshot},
    time::sleep,
};
use tower::Service;

use crate::tower::{
    adapter::{Exchange, Respond},
    dispatch::Control,
    reply,
};

/// What the request handlers and the control service share.
#[derive(Clone, Default)]
pub(crate) struct Calls(Arc<Mutex<CallState>>);

impl Calls {
    pub(crate) fn lock(&self) -> MutexGuard<'_, CallState> {
        self.0.lock().unwrap()
    }
}

#[derive(Default)]
pub(crate) struct CallState {
    /// ACK waiters, by Call-ID.
    acks: HashMap<String, oneshot::Sender<()>>,
    /// CANCELs that came before their handler started.
    pub(crate) cancelled: HashSet<ServerTransactionId>,
    /// Handlers waiting for a CANCEL.
    pub(crate) cancels: HashMap<ServerTransactionId, oneshot::Sender<()>>,
}

/// Opens and closes the request service's readiness.
#[derive(Default)]
pub(crate) struct Gate {
    pub(crate) closed: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Gate {
    pub(crate) fn open(&self) {
        self.closed.store(false, Ordering::SeqCst);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

/// Shared counters of the request service.
#[derive(Default)]
pub(crate) struct Usage {
    pub(crate) readies: AtomicUsize,
    pub(crate) calls: AtomicUsize,
    pub(crate) running: AtomicUsize,
    pub(crate) most_running: AtomicUsize,
}

/// The leaf handler. It is generic over the sender, so it works with whatever
/// wrappers the layers add, and it is not `Clone`.
pub(crate) struct Answer {
    /// Set by `poll_ready` and taken by `call`, so a call without readiness
    /// on this instance panics.
    pub(crate) ready: bool,
    pub(crate) calls: Calls,
    pub(crate) gate: Arc<Gate>,
    pub(crate) usage: Arc<Usage>,
    pub(crate) release: Arc<Notify>,
    /// Where a handler leaves its `ServerEvents` when it returns.
    pub(crate) finished: mpsc::UnboundedSender<ServerEvents>,
}

impl<R> Service<Exchange<R>> for Answer
where
    R: Respond + Send + Sync + 'static,
{
    type Response = ();
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<(), Infallible>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Infallible>> {
        if self.gate.closed.load(Ordering::SeqCst) {
            *self.gate.waker.lock().unwrap() = Some(cx.waker().clone());
            if self.gate.closed.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        if !mem::replace(&mut self.ready, true) {
            self.usage.readies.fetch_add(1, Ordering::SeqCst);
        }
        Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        exchange: Exchange<R>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Infallible>> + Send>> {
        assert!(
            mem::replace(&mut self.ready, false),
            "readiness was polled on the instance that is called"
        );
        self.usage.calls.fetch_add(1, Ordering::SeqCst);
        let running = self.usage.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.usage.most_running.fetch_max(running, Ordering::SeqCst);

        let calls = self.calls.clone();
        let usage = self.usage.clone();
        let release = self.release.clone();
        let finished = self.finished.clone();
        Box::pin(async move {
            handle(exchange, &calls, &release, finished).await;
            usage.running.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

/// What a request does depends on the user part of its Request-URI:
///
/// * `answer`: 180, then a 2xx with two To tags as a forking proxy would
///   relay them, waits for the ACK, and tries a 183 that comes too late.
/// * `hold`: waits for the test to release it, then answers 200.
/// * `ring`: 180, then waits for a CANCEL and answers 487.
/// * `stall`: never answers.
async fn handle<R: Respond>(
    exchange: Exchange<R>,
    calls: &Calls,
    release: &Notify,
    finished: mpsc::UnboundedSender<ServerEvents>,
) {
    let Exchange { request, responder, events, transaction_id, .. } = exchange;
    let user = request.uri().as_str().to_owned();
    let call_id = request.headers().get(CALL_ID).unwrap().as_str().to_owned();

    if user.starts_with("sip:answer@") {
        let _ = responder.respond(reply(&request, 180, &tag("a"))).await;
        sleep(Duration::from_millis(100)).await;
        let (acked, ack) = oneshot::channel();
        calls.lock().acks.insert(call_id, acked);
        let _ = responder.respond(reply(&request, 200, &tag("a"))).await;
        let _ = responder.respond(reply(&request, 200, &tag("b"))).await;
        let _ = ack.await;
        let _ = responder.respond(reply(&request, 183, &tag("a"))).await;
    } else if user.starts_with("sip:hold@") {
        release.notified().await;
        let _ = responder.respond(reply(&request, 200, &tag("a"))).await;
    } else if user.starts_with("sip:ring@") {
        let (cancel, cancelled) = oneshot::channel();
        // A CANCEL can reach the control lane before this handler starts.
        let already = {
            let mut calls = calls.lock();
            let already = calls.cancelled.remove(&transaction_id);
            if !already {
                calls.cancels.insert(transaction_id, cancel);
            }
            already
        };
        if !already {
            let _ = responder.respond(reply(&request, 180, &tag("a"))).await;
            let _ = cancelled.await;
        }
        let _ = responder.respond(reply(&request, 487, &tag("a"))).await;
    } else {
        pending::<()>().await;
    }
    let _ = finished.send(events);
}

/// The control lane's service. It answers CANCELs and routes ACKs to the
/// handler waiting for them.
pub(crate) struct ControlService {
    pub(crate) ready: bool,
    pub(crate) calls: Calls,
    pub(crate) acks: Arc<AtomicUsize>,
}

impl Service<Control<Responder>> for ControlService {
    type Response = ();
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<(), Infallible>> + Send>>;

    fn poll_ready(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), Infallible>> {
        self.ready = true;
        Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        event: Control<Responder>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Infallible>> + Send>> {
        assert!(mem::replace(&mut self.ready, false));
        let calls = self.calls.clone();
        let acks = self.acks.clone();
        Box::pin(async move {
            match event {
                Control::Cancel { exchange, target } => {
                    let ok = reply(&exchange.request, 200, &Tag::random());
                    let _ = exchange.responder.respond(ok).await;
                    // The handler may not have started. It then finds the
                    // mark when it does.
                    let mut calls = calls.lock();
                    match calls.cancels.remove(&target) {
                        Some(cancel) => {
                            let _ = cancel.send(());
                        }
                        None => {
                            calls.cancelled.insert(target);
                        }
                    }
                }
                Control::Ack(ack) => {
                    acks.fetch_add(1, Ordering::SeqCst);
                    let call_id =
                        ack.request.headers().get(CALL_ID).unwrap().as_str();
                    if let Some(waiter) = calls.lock().acks.remove(call_id) {
                        let _ = waiter.send(());
                    }
                }
                Control::UnmatchedCancel(cancel) => {
                    let _ = cancel
                        .reply
                        .send(reply(&cancel.request, 481, &Tag::random()))
                        .await;
                }
                Control::Untracked(_) => {}
            }
            Ok(())
        })
    }
}

fn tag(name: &str) -> Tag {
    name.parse().unwrap()
}
