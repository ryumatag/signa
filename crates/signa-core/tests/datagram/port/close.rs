/*!
Quiescing and closing a port. A close drains the writes already admitted,
then closes the backend, and gives up at its deadline.
*/

use std::{
    net::SocketAddr,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::Bytes;
use signa_core::{
    endpoint::{
        Endpoint, PathSelection, ServerEvent, ShutdownOutcome, observe,
        port::{Capture, DatagramPort},
    },
    transport::{
        Limits,
        datagram::{
            Capabilities, Datagram, DatagramIo, DatagramWrite, RecvError,
            Submit, WriteId, WriteOutcome,
        },
    },
};
use tokio::{
    sync::Notify,
    task::{JoinHandle, yield_now},
    time::{advance, sleep, timeout},
};

use crate::{
    datagram::{
        LOCAL, PEER, arriving, datagram, ok, options,
        port::{intercept, next, upstream},
        send_options,
        wire::{Wire, Writes},
    },
    support::request,
};

// Quiescing refuses new endpoints and new raw paths, and nothing else.
// Delivery, the endpoint's responses and paths, and raw sends on an existing
// path go on, so that registered endpoints can finish their work.
#[tokio::test]
async fn quiescing_refuses_only_new_endpoints_and_raw_paths() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let (endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;

    port.quiesce();

    let refused = Endpoint::builder().bind_on(&port).unwrap_err();
    assert!(refused.is_closed());
    let selection = PathSelection::new(LOCAL, PEER);
    let refused = port.prepare_path(selection.clone()).await.unwrap_err();
    assert!(refused.is_closed());
    assert_eq!(
        refused.to_string(),
        "the port is quiesced and takes no new paths"
    );
    assert!(endpoint.prepare_path(selection).await.is_ok());
    wire.deliver(datagram(options("quiet")));
    next(&mut ingress).await.try_deliver(&to_endpoint).unwrap();
    let request = request(&mut incoming).await;
    let (responder, _) = request.transaction.into_parts();
    responder.respond(ok(&request.request)).await.unwrap();
    let raw = Bytes::from_static(b"raw");
    port.send_bytes(raw, &upstream).unwrap().await.unwrap();
    assert_eq!(wire.sent(2).await.len(), 2);
}

// Closing drains the writes already admitted, then closes the backend, and
// everything of the port turns invalid: a raw send is refused, a datagram the
// application still holds can no longer be delivered, and the ingress ends.
#[tokio::test]
async fn closing_the_port_drains_its_writes_then_closes_the_backend() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let (_endpoint, _incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    wire.deliver(datagram(options("held")));
    let held = next(&mut ingress).await;
    wire.writes(Writes::Delay);
    let raw = port.send_bytes(Bytes::from_static(b"raw"), &upstream).unwrap();
    wire.sent(1).await;

    let close = tokio::spawn(port.close(Duration::from_secs(2)));
    yield_now().await;
    assert!(!wire.closed());
    wire.finish(Ok(()));

    raw.await.unwrap();
    assert_eq!(close.await.unwrap(), ShutdownOutcome::Drained);
    assert!(wire.closed());
    let refused = port.send_bytes(Bytes::from_static(b"late"), &upstream);
    assert!(refused.unwrap_err().is_closed());
    let refused = held.try_deliver(&to_endpoint).unwrap_err();
    assert!(refused.error().is_closed());
    assert!(ingress.recv().await.is_none());
}

// At the close's deadline the writes left fail, and a backend that does not
// finish closing is dropped, as an endpoint drops its own. The outcome says
// the deadline came first. The raw write the backend took and never reported
// may have gone out, and its waiter learns that its outcome is unknown, not
// that it failed.
#[tokio::test]
async fn a_port_close_gives_up_at_its_deadline() {
    let wire = Wire::default();
    let (port, _ingress) = intercept(&wire);
    let upstream = upstream(&port).await;
    wire.writes(Writes::Delay);
    wire.state.lock().unwrap().stuck = true;
    let raw = port.send_bytes(Bytes::from_static(b"raw"), &upstream).unwrap();
    wire.sent(1).await;

    let close = port.close(Duration::from_millis(50));
    let outcome = timeout(Duration::from_secs(2), close).await.unwrap();

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    let error = raw.await.unwrap_err();
    assert!(error.is_outcome_unknown());
    assert!(!error.is_transport() && !error.is_closed());
}

/// A backend over a [`Wire`] whose `Drop` holds until the test opens its
/// gate, so that a test can watch what a close does while the backend is
/// being dropped.
struct Gated {
    wire: Wire,
    dropping: Arc<Notify>,
    gate: std::sync::mpsc::Receiver<()>,
    dropped: Arc<AtomicBool>,
}

/// The test's side of a [`Gated`] backend.
struct Gate {
    dropping: Arc<Notify>,
    open: std::sync::mpsc::Sender<()>,
    dropped: Arc<AtomicBool>,
}

fn gated(wire: Wire) -> (Gated, Gate) {
    let dropping = Arc::new(Notify::new());
    let (open, gate) = std::sync::mpsc::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let backend = Gated {
        wire,
        dropping: dropping.clone(),
        gate,
        dropped: dropped.clone(),
    };
    (backend, Gate { dropping, open, dropped })
}

impl Drop for Gated {
    // The task that drops the backend waits here. `block_in_place` hands the
    // worker's other duties to another thread first. A worker blocked
    // outright can be the one that drives the timers, and then no timeout in
    // the test would fire. A test that dropped its gate has opened it too.
    fn drop(&mut self) {
        self.dropping.notify_one();
        tokio::task::block_in_place(|| {
            let _ = self.gate.recv();
        });
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl DatagramIo for Gated {
    fn local_addr(&self) -> SocketAddr {
        self.wire.local_addr()
    }

    fn capabilities(&self) -> Capabilities {
        self.wire.capabilities()
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Datagram, RecvError>> {
        self.wire.poll_recv(cx)
    }

    fn poll_submit(
        &mut self,
        cx: &mut Context<'_>,
        write: DatagramWrite,
    ) -> Submit {
        self.wire.poll_submit(cx, write)
    }

    fn poll_complete(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<(WriteId, WriteOutcome)> {
        self.wire.poll_complete(cx)
    }

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.wire.poll_close(cx)
    }
}

/// Checks that `closing` resolves only once the gated backend has dropped,
/// and returns its outcome.
async fn resolves_after_drop(
    gate: Gate,
    mut closing: JoinHandle<ShutdownOutcome>,
    case: &str,
) -> ShutdownOutcome {
    timeout(Duration::from_secs(2), gate.dropping.notified())
        .await
        .unwrap_or_else(|_| panic!("{case}: the backend is dropped"));
    let early = timeout(Duration::from_millis(50), &mut closing).await.ok();
    // Opened before any assertion, so that a failure cannot leave the task
    // that drops the backend blocked.
    gate.open.send(()).unwrap();
    let resolved_early = early.is_some();
    let outcome = match early {
        Some(outcome) => outcome,
        None => timeout(Duration::from_secs(2), closing).await.unwrap(),
    };

    assert!(
        !resolved_early,
        "{case}: resolved while the backend was dropping"
    );
    assert!(gate.dropped.load(Ordering::SeqCst), "{case}");
    outcome.unwrap()
}

// A port's close resolves only once its backend has dropped. The backend's
// `Drop` is the last thing that stops its tasks when it does not finish
// closing in time, and a socket is released only as it drops, so a closer
// told the outcome before could rebind the address or count on silence too
// early. An endpoint's shutdown and a capture's close keep the same order.
// Each closes in time with a wire that closes, and at the deadline with one
// that never does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_resolves_after_its_backend_has_dropped() {
    for stuck in [false, true] {
        let expected = if stuck {
            ShutdownOutcome::DeadlineExpired
        } else {
            ShutdownOutcome::Drained
        };
        let backend = || {
            let wire = Wire::default();
            wire.state.lock().unwrap().stuck = stuck;
            gated(wire)
        };

        let (gated, gate) = backend();
        let (port, _ingress) =
            DatagramPort::builder().udp_io(gated).intercept().unwrap();
        let closing = tokio::spawn(port.close(Duration::from_millis(50)));
        let case = format!("port {stuck}");
        assert_eq!(resolves_after_drop(gate, closing, &case).await, expected);

        let (gated, gate) = backend();
        let (endpoint, _incoming) =
            Endpoint::builder().udp_io(gated).bind().unwrap();
        let closing =
            tokio::spawn(endpoint.shutdown(Duration::from_millis(50)));
        let case = format!("endpoint {stuck}");
        assert_eq!(resolves_after_drop(gate, closing, &case).await, expected);

        let (gated, gate) = backend();
        let capture = Capture::builder().udp_io(gated).open().unwrap();
        let closing = tokio::spawn(capture.close(Duration::from_millis(50)));
        let case = format!("capture {stuck}");
        assert_eq!(resolves_after_drop(gate, closing, &case).await, expected);
    }
}

// Both closes start when they are called, not when their futures are first
// polled. A port takes no new endpoint from the call on, and a capture's
// deadline runs from it, so a close first polled after the deadline gives up
// at once on a backend that never finishes closing.
#[tokio::test(start_paused = true)]
async fn a_close_starts_when_it_is_called() {
    let (port, _ingress) = intercept(&Wire::default());
    let stuck = Wire::default();
    stuck.state.lock().unwrap().stuck = true;
    let capture = Capture::builder().udp_io(stuck).open().unwrap();

    let port_close = port.close(Duration::from_secs(1));
    let capture_close = capture.close(Duration::from_millis(50));
    advance(Duration::from_millis(60)).await;

    assert!(Endpoint::builder().bind_on(&port).unwrap_err().is_closed());
    let mut capture_close = pin!(capture_close);
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(
        capture_close.as_mut().poll(&mut cx),
        Poll::Ready(ShutdownOutcome::DeadlineExpired)
    );
    assert_eq!(port_close.await, ShutdownOutcome::Drained);
}

// A task that receives or closes can move between threads.
#[tokio::test]
async fn the_receive_and_close_futures_are_send() {
    fn send<T: Send>(_: T) {}
    let (port, mut ingress) = intercept(&Wire::default());
    let mut capture =
        Capture::builder().udp_io(Wire::default()).open().unwrap();
    let mut observer = port.observe(observe::Config::new()).await.unwrap();

    send(ingress.recv());
    send(capture.recv());
    send(observer.recv());
    send(capture.close(Duration::ZERO));
    send(port.close(Duration::ZERO));
}

/// A backend that panics in `poll_recv` once its fuse is lit, as an adapter
/// with a bug might.
struct Panicking<B> {
    backend: B,
    fuse: Arc<AtomicBool>,
}

impl<B: DatagramIo> DatagramIo for Panicking<B> {
    fn local_addr(&self) -> SocketAddr {
        self.backend.local_addr()
    }

    fn capabilities(&self) -> Capabilities {
        self.backend.capabilities()
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Datagram, RecvError>> {
        let received = self.backend.poll_recv(cx);
        if self.fuse.load(Ordering::SeqCst) && received.is_ready() {
            panic!("the backend panics, as the test asked");
        }
        received
    }

    fn poll_submit(
        &mut self,
        cx: &mut Context<'_>,
        write: DatagramWrite,
    ) -> Submit {
        self.backend.poll_submit(cx, write)
    }

    fn poll_complete(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<(WriteId, WriteOutcome)> {
        self.backend.poll_complete(cx)
    }

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.backend.poll_close(cx)
    }
}

// A port whose backend panics still closes, as one that ran out of time
// would. Its task drops the backend before it reports the close expired, so
// a closer neither waits forever nor hears of the close while the backend is
// still dropping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_whose_backend_panics_still_closes() {
    let wire = Wire::default();
    let (gated, gate) = gated(wire.clone());
    let fuse = Arc::new(AtomicBool::new(true));
    let backend = Panicking { backend: gated, fuse };
    let (port, _ingress) =
        DatagramPort::builder().udp_io(backend).intercept().unwrap();

    wire.deliver(datagram(options("panic")));
    // The close comes once the task has panicked. One that came first would
    // stop reception before the panic.
    timeout(Duration::from_secs(2), gate.dropping.notified())
        .await
        .expect("the backend is dropped");
    let mut closing = tokio::spawn(port.close(Duration::from_secs(60)));
    let early = timeout(Duration::from_millis(50), &mut closing).await.ok();
    // Opened before any assertion, so that a failure cannot leave the task
    // that drops the backend blocked.
    gate.open.send(()).unwrap();
    let resolved_early = early.is_some();
    let outcome = match early {
        Some(outcome) => outcome,
        None => timeout(Duration::from_secs(2), closing).await.unwrap(),
    };

    assert!(!resolved_early, "resolved while the backend was dropping");
    assert!(gate.dropped.load(Ordering::SeqCst));
    assert_eq!(outcome.unwrap(), ShutdownOutcome::DeadlineExpired);
}

// The endpoints on a port whose backend panics learn how their writes ended
// rather than wait forever. A write the backend had taken may have gone out,
// so its outcome is unknown. One still waiting for room in the port's limits
// never went out.
#[tokio::test]
async fn an_endpoint_learns_its_writes_when_the_port_s_backend_panics() {
    let wire = Wire::default();
    let fuse = Arc::new(AtomicBool::new(false));
    let backend = Panicking { backend: wire.clone(), fuse: fuse.clone() };
    let (port, _ingress) = DatagramPort::builder()
        .udp_io(backend)
        .write_limits(Limits { count: 1, bytes: 64 * 1024 })
        .intercept()
        .unwrap();
    let (endpoint, _incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    wire.writes(Writes::Delay);
    let taken = send_options(&endpoint, "taken");
    wire.sent(1).await;
    let waiting = send_options(&endpoint, "waiting");
    sleep(Duration::from_millis(20)).await;

    fuse.store(true, Ordering::SeqCst);
    wire.deliver(datagram(options("panic")));

    let taken = timeout(Duration::from_secs(2), taken).await.unwrap();
    let waiting = timeout(Duration::from_secs(2), waiting).await.unwrap();
    let (taken, waiting) =
        (taken.unwrap().unwrap_err(), waiting.unwrap().unwrap_err());
    assert!(taken.is_outcome_unknown() && !taken.is_transport(), "{taken}");
    assert!(
        waiting.is_transport() && !waiting.is_outcome_unknown(),
        "{waiting}"
    );
    assert_eq!(wire.count(), 1);
    let close = port.close(Duration::from_secs(1));
    let closed = timeout(Duration::from_secs(2), close).await.unwrap();
    assert_eq!(closed, ShutdownOutcome::DeadlineExpired);
}

// A port on a socket of its own has released its address once its close
// resolves, so another socket can bind it at once. A few rounds give a close
// that published early more chances to lose the race.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_port_s_address_can_be_bound_again() {
    for _ in 0..20 {
        let (port, _ingress) = DatagramPort::builder()
            .udp("127.0.0.1:0".parse().unwrap())
            .intercept()
            .unwrap();
        let addr = port.local_addr();

        let outcome = port.close(Duration::from_secs(1)).await;

        assert_eq!(outcome, ShutdownOutcome::Drained);
        std::net::UdpSocket::bind(addr).unwrap();
    }
}

// A close starts when it is called. Dropping its future does not stop it,
// and a call after the close finished gets the same outcome at once.
#[tokio::test]
async fn a_dropped_close_still_closes_the_port() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);

    drop(port.close(Duration::from_secs(1)));

    let ended = timeout(Duration::from_secs(2), ingress.recv()).await.unwrap();
    assert!(ended.is_none());
    timeout(Duration::from_secs(2), async {
        while !wire.closed() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the backend closes");
    let again = timeout(Duration::from_millis(50), port.close(Duration::ZERO));
    assert_eq!(again.await.unwrap(), ShutdownOutcome::Drained);
}

// A later close with an earlier deadline brings the close forward, both
// while the port drains a write its wire holds and while the wire never
// finishes closing. Both callers get the outcome by the earlier deadline.
#[tokio::test]
async fn a_later_close_brings_the_deadline_forward() {
    for draining in [true, false] {
        let wire = Wire::default();
        let (port, mut ingress) = intercept(&wire);
        let upstream = upstream(&port).await;
        wire.writes(Writes::Delay);
        if !draining {
            wire.state.lock().unwrap().stuck = true;
        }
        let held = port.send_bytes(Bytes::from_static(b"raw"), &upstream);
        wire.sent(1).await;
        if !draining {
            wire.finish(Ok(()));
        }

        let first = tokio::spawn(port.close(Duration::from_secs(60)));
        // The ingress ends as the task turns to closing, and a stuck wire
        // reports itself closed once the drain is over and its close began.
        assert!(
            timeout(Duration::from_secs(2), ingress.recv())
                .await
                .unwrap()
                .is_none()
        );
        if !draining {
            timeout(Duration::from_secs(2), async {
                while !wire.closed() {
                    sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("the wire starts to close");
        }
        let second = port.close(Duration::from_millis(50));

        let second = timeout(Duration::from_secs(2), second).await;
        let first = timeout(Duration::from_secs(2), first).await;
        assert_eq!(
            second.unwrap(),
            ShutdownOutcome::DeadlineExpired,
            "{draining}"
        );
        assert_eq!(first.unwrap().unwrap(), ShutdownOutcome::DeadlineExpired);
        let held = held.unwrap().await;
        if draining {
            assert!(held.unwrap_err().is_transport(), "the wire closed it");
        } else {
            held.unwrap();
        }
    }
}

// A port runs while a handle or a registered endpoint is left. Once the last
// endpoint has stopped and every handle is gone, it closes its backend.
#[tokio::test]
async fn a_port_closes_once_nothing_uses_it() {
    let wire = Wire::default();
    let (port, ingress) = intercept(&wire);
    let (endpoint, _incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    drop(port);
    drop(ingress);
    sleep(Duration::from_millis(50)).await;
    assert!(!wire.closed());

    let outcome = endpoint.shutdown(Duration::from_secs(1)).await;

    assert_eq!(outcome, ShutdownOutcome::Drained);
    timeout(Duration::from_secs(2), async {
        while !wire.closed() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the wire closed");
}

// A port that closes while an endpoint still has writes in it tells the
// endpoint how each ended, so that nothing waits for an outcome forever: the
// write the wire held never went out, and the one it took and never reported
// may have. That holds whether the wire finishes closing or is dropped at the
// deadline.
#[tokio::test]
async fn a_closing_port_ends_the_writes_of_its_endpoints() {
    for stuck in [false, true] {
        let wire = Wire::default();
        let (port, _ingress) = intercept(&wire);
        let (endpoint, _incoming, _) =
            Endpoint::builder().bind_on(&port).unwrap();
        wire.writes(Writes::Delay);
        let taken = send_options(&endpoint, "taken");
        wire.sent(1).await;
        wire.writes(Writes::Hold);
        let held = send_options(&endpoint, "held");
        wire.until(|state| state.submit.is_some()).await;
        wire.state.lock().unwrap().stuck = stuck;

        let close = port.close(Duration::from_millis(50));
        let outcome = timeout(Duration::from_secs(2), close).await.unwrap();

        assert_eq!(outcome, ShutdownOutcome::DeadlineExpired, "{stuck}");
        let taken = timeout(Duration::from_secs(2), taken).await.unwrap();
        let held = timeout(Duration::from_secs(2), held).await.unwrap();
        // A wire that closes reports what it held as not written. One that
        // never finishes closing leaves it unknown.
        let taken = taken.unwrap().unwrap_err();
        if stuck {
            assert!(taken.is_outcome_unknown() && !taken.is_transport());
        } else {
            assert!(taken.is_transport() && !taken.is_outcome_unknown());
        }
        // The port never offered the held write, so it did not go out.
        assert!(held.unwrap().unwrap_err().is_transport(), "{stuck}");
        assert_eq!(wire.count(), 1);
    }
}

// A response the port's wire took and never reported, when the port closes
// at its deadline, is observed as an unknown outcome. The endpoint is still
// running, so it is not told that it closed, and the server transaction keeps
// its state.
#[tokio::test]
async fn a_forced_port_close_leaves_an_endpoint_s_response_unknown() {
    let wire = Wire::default();
    let (port, mut ingress) = intercept(&wire);
    let (endpoint, mut incoming, to_endpoint) =
        Endpoint::builder().bind_on(&port).unwrap();
    wire.deliver(arriving(options("forced"), "nic0"));
    let datagram = next(&mut ingress).await;
    datagram.try_deliver(&to_endpoint).unwrap();
    let request = request(&mut incoming).await;
    let (responder, mut events) = request.transaction.into_parts();
    wire.writes(Writes::Delay);
    wire.state.lock().unwrap().stuck = true;
    responder.respond(ok(&request.request)).await.unwrap();
    wire.sent(1).await;

    let close = port.close(Duration::from_millis(50));
    let outcome = timeout(Duration::from_secs(2), close).await.unwrap();

    assert_eq!(outcome, ShutdownOutcome::DeadlineExpired);
    let event = timeout(Duration::from_secs(2), events.next()).await.unwrap();
    assert!(
        matches!(
            event,
            Some(ServerEvent::OutcomeUnknown { operation: Some(_), .. })
        ),
        "{event:?}"
    );
    drop(endpoint);
}
