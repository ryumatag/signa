/*!
Readiness, which Tower asks of a service before each call. The adapter
polls one instance ready and calls that instance, and what it does with a
readiness error is its own policy, which the UA answers for on the wire.
*/

use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use signa_ua::IncomingInvite;
use tokio::time::timeout;
use tower::Service;

use crate::{
    support::{
        WAIT,
        message::{ack_for, header, in_dialog, invite_to_ua, sdp},
        peer::Peer,
        start_fast,
    },
    tower::Serving,
};

type Handling = Pin<Box<dyn Future<Output = Result<(), Infallible>> + Send>>;

#[derive(Debug, PartialEq)]
enum Step {
    Ready(usize),
    Call(usize),
}

/// A service that is not `Clone`, and takes a call only on the instance its
/// last `poll_ready` made ready. It is not ready on every other poll, so the
/// adapter polls it twice for each call. Each instance logs the polls that
/// made it ready and the calls it took, under its own number.
struct Picky {
    instance: usize,
    ready: bool,
    polls: usize,
    log: Arc<Mutex<Vec<Step>>>,
}

impl Service<IncomingInvite> for Picky {
    type Response = ();
    type Error = Infallible;
    type Future = Handling;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Infallible>> {
        self.polls += 1;
        if self.polls % 2 == 1 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if !self.ready {
            self.ready = true;
            self.log.lock().unwrap().push(Step::Ready(self.instance));
        }
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, invite: IncomingInvite) -> Handling {
        assert!(self.ready, "a call on instance {} not ready", self.instance);
        self.ready = false;
        self.log.lock().unwrap().push(Step::Call(self.instance));
        Box::pin(async move {
            invite.try_accept(sdp()).unwrap().await.unwrap();
            Ok(())
        })
    }
}

/// Each INVITE reaches the one instance of a service that is not `Clone`,
/// and only after a `poll_ready` of that instance said it was ready, polled
/// again where the first said it was not. Tower allows nothing else (the
/// contract of `Service::call`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tower_uses_same_service_for_ready_and_call() {
    let (ua, udp, _) = start_fast();
    let log = Arc::new(Mutex::new(Vec::new()));
    let service =
        Picky { instance: 7, ready: false, polls: 0, log: log.clone() };
    let serving = Serving::start(ua, service);
    let peer = Peer::new().await;
    let calls = ["first", "second", "third", "fourth", "fifth"];

    for call in calls {
        peer.send(&invite_to_ua(peer.address(), call), udp).await;
        let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
        assert_eq!(header(&ok, "Call-ID"), [call]);
        peer.send(&ack_for(&ok, peer.address(), call, 1), udp).await;
    }

    drop(serving);
    let log = log.lock().unwrap();
    let expected: Vec<Step> =
        calls.iter().flat_map(|_| [Step::Ready(7), Step::Call(7)]).collect();
    // The adapter polls the next readiness as soon as it called, so a last
    // `Ready` may follow.
    assert_eq!(log[..expected.len()], expected[..], "{log:?}");
    assert!(log[expected.len()..].iter().all(|step| *step == Step::Ready(7)));
}

/// What a [`Switched`] service answers `poll_ready` with.
#[derive(Clone, Copy, PartialEq)]
enum Readiness {
    /// Ready for this many more calls.
    Calls(usize),
    Failed,
}

/// The readiness the test sets, and the task waiting for it.
#[derive(Clone)]
struct Switch(Arc<Mutex<(Readiness, Option<Waker>)>>);

impl Switch {
    fn set(&self, readiness: Readiness) {
        let mut state = self.0.lock().unwrap();
        state.0 = readiness;
        if let Some(waker) = state.1.take() {
            waker.wake();
        }
    }
}

/// A service ready as its [`Switch`] says, whose handler accepts.
struct Switched(Switch);

impl Service<IncomingInvite> for Switched {
    type Response = ();
    type Error = &'static str;
    type Future =
        Pin<Box<dyn Future<Output = Result<(), &'static str>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), &'static str>> {
        let mut state = (self.0).0.lock().unwrap();
        match state.0 {
            Readiness::Failed => Poll::Ready(Err("the service failed")),
            Readiness::Calls(0) => {
                state.1 = Some(cx.waker().clone());
                Poll::Pending
            }
            Readiness::Calls(_) => Poll::Ready(Ok(())),
        }
    }

    fn call(
        &mut self,
        invite: IncomingInvite,
    ) -> Pin<Box<dyn Future<Output = Result<(), &'static str>> + Send>> {
        let mut state = (self.0).0.lock().unwrap();
        if let Readiness::Calls(left) = &mut state.0 {
            *left -= 1;
        }
        Box::pin(async move {
            invite.try_accept(sdp()).unwrap().await.unwrap();
            Ok(())
        })
    }
}

/// The service takes one call and is then not ready, so the next INVITE
/// waits in the UA's event queue, undecided. Its readiness then fails. The
/// adapter drops the service and its events, so the waiting INVITE gets the
/// UA's 500 for a dropped decision, and a later one the 503 of an INVITE
/// nobody can decide. The driver goes on, and the session the first call
/// made still takes its BYE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readiness_error_is_reported_without_driver_panic() {
    let (ua, udp, _) = start_fast();
    let switch = Switch(Arc::new(Mutex::new((Readiness::Calls(1), None))));
    let serving = Serving::start(ua, Switched(switch.clone()));
    let peer = Peer::new().await;
    let me = peer.address();
    peer.send(&invite_to_ua(me, "served"), udp).await;
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    peer.send(&ack_for(&ok, me, "served", 1), udp).await;
    // A copy of the 2xx may cross the ACK.
    peer.drain(Duration::from_millis(100)).await;

    peer.send(&invite_to_ua(me, "waiting"), udp).await;
    // Neither a final from a handler nor any other.
    peer.quiet("SIP/2.0 2", Duration::from_millis(200)).await;
    switch.set(Readiness::Failed);
    let (dropped, _) = peer.recv_starting("SIP/2.0 500").await;
    assert_eq!(header(&dropped, "Call-ID"), ["waiting"]);
    peer.send(&invite_to_ua(me, "later"), udp).await;
    let (refused, _) = peer.recv_starting("SIP/2.0 503").await;
    assert_eq!(header(&refused, "Call-ID"), ["later"]);

    peer.send(&in_dialog("BYE", "UDP", &ok, me, "served", 2), udp).await;
    // A copy of the first 2xx may still be on its way.
    while header(&peer.recv_starting("SIP/2.0 200").await.0, "CSeq")
        != ["2 BYE"]
    {}
    assert!(!serving.driver.is_finished());
    let served = timeout(WAIT, serving.adapter).await.unwrap().unwrap();
    assert_eq!((served.calls, served.completed), (1, 1));
    assert_eq!(served.readiness.as_deref(), Some("\"the service failed\""));
}
