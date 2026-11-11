/*!
Limits on the handlers, as Tower's `ConcurrencyLimit` and `Buffer` set
them, hold up the handlers only. The UA answers ACK, CANCEL and BYE itself
and sends the copies of its 2xx and its own requests whatever the handlers
do, so a full limit holds none of them up. The INVITEs the adapter does not
take meanwhile wait in the UA's event queue, and one beyond it gets the
UA's 503 (RFC 3261 section 21.5.4), as when nobody reads the events.
*/

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use signa_core::endpoint::Endpoint;
use signa_ua::{
    CancelResult, Config, Error, IncomingInvite, Resolve, Session, Ua, attach,
};
use tokio::{
    net::TcpListener,
    sync::mpsc,
    time::{sleep, timeout},
};
use tower::{
    BoxError, Service, ServiceBuilder, ServiceExt, service_fn,
    util::BoxService,
};

use crate::{
    support::{
        LOADED, WAIT, config,
        flood::FLOODING,
        message::{
            answer, cancel_of, header, in_dialog, invite_over, ok_to, plan_to,
            reply_with, sdp,
        },
        peer::{Peer, TcpPeer, Wire},
    },
    tower::{Gate, Running, Serving},
};

/// What the handlers run behind.
#[derive(Clone, Copy, Debug)]
enum Stack {
    /// A `ConcurrencyLimit` of one handler.
    Limit,
    /// A `Buffer` whose channel holds one call, in front of the same limit.
    /// Its worker holds one more call while the limit is full.
    Buffered,
}

/// Counts what the service behind it is asked: the polls that found it not
/// ready, and the calls.
struct Watched<S> {
    inner: S,
    not_ready: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}

impl<S: Service<IncomingInvite>> Service<IncomingInvite> for Watched<S> {
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), S::Error>> {
        let ready = self.inner.poll_ready(cx);
        if ready.is_pending() {
            self.not_ready.fetch_add(1, Ordering::SeqCst);
        }
        ready
    }

    fn call(&mut self, invite: IncomingInvite) -> S::Future {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.call(invite)
    }
}

/// A UA on UDP and TCP whose endpoint and configuration run on the
/// [`LOADED`] timers, whose ACK deadline is long enough for the limits to
/// fill first.
fn loaded<R: Resolve>(config: Config<R>) -> (Ua, SocketAddr, SocketAddr) {
    let local = "127.0.0.1:0".parse().unwrap();
    let (endpoint, incoming) = Endpoint::builder()
        .udp(local)
        .tcp(local)
        .timers(*LOADED)
        .bind()
        .unwrap();
    let (udp, tcp) =
        (endpoint.udp_addr().unwrap(), endpoint.tcp_addr().unwrap());
    let ua = attach(endpoint, incoming, config.timers(*LOADED)).unwrap();
    (ua, udp, tcp)
}

/// Receives the next message, whatever it is.
async fn next(wire: &mut Wire) -> String {
    match wire {
        Wire::Udp { peer, .. } => peer.recv().await.0,
        Wire::Tcp(peer) => peer.recv().await,
    }
}

/// Receives messages until one starts with `start` and has `cseq` and the
/// Call-ID `call`.
async fn answer_to(
    wire: &mut Wire,
    start: &str,
    cseq: &str,
    call: &str,
) -> String {
    loop {
        let message = next(wire).await;
        if message.starts_with(start)
            && header(&message, "CSeq") == [cseq]
            && header(&message, "Call-ID") == [call]
        {
            return message;
        }
    }
}

/// The far end of the INVITEs the UA sends, over UDP or over a TCP
/// connection the UA opens.
enum Far {
    Udp { peer: Peer, from: Option<SocketAddr> },
    Tcp { listener: TcpListener, connection: Option<TcpPeer> },
}

impl Far {
    async fn new(transport: &str) -> Far {
        if transport == "UDP" {
            Far::Udp { peer: Peer::new().await, from: None }
        } else {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            Far::Tcp { listener, connection: None }
        }
    }

    /// What follows `sip:peer@` in a URI that reaches it.
    fn target(&self) -> String {
        match self {
            Far::Udp { peer, .. } => peer.address().to_string(),
            Far::Tcp { listener, .. } => {
                format!("{};transport=tcp", listener.local_addr().unwrap())
            }
        }
    }

    async fn recv_starting(&mut self, start: &str) -> String {
        match self {
            Far::Udp { peer, from } => {
                let (message, source) = peer.recv_starting(start).await;
                *from = Some(source);
                message
            }
            Far::Tcp { listener, connection } => {
                if connection.is_none() {
                    let accepted = timeout(WAIT, listener.accept()).await;
                    let (stream, _) = accepted.unwrap().unwrap();
                    *connection = Some(TcpPeer { stream, buffer: Vec::new() });
                }
                connection.as_mut().unwrap().recv_starting(start).await
            }
        }
    }

    async fn send(&mut self, message: &str) {
        match self {
            Far::Udp { peer, from } => peer.send(message, from.unwrap()).await,
            Far::Tcp { connection, .. } => {
                connection.as_mut().unwrap().send(message).await
            }
        }
    }
}

/// While the only handler holds an INVITE undecided, the handler limit is
/// full. The next INVITEs wait in the buffer, if there is one, the ones after
/// them in the UA's event queue, and one beyond that gets the UA's 503.
/// Meanwhile, over UDP and over TCP, the UA as the callee sends its 2xx again
/// until the ACK, answers a CANCEL of the held INVITE with a 200 and the
/// INVITE with a 487, and a BYE with a 200. As the caller, it acknowledges a
/// 2xx, sends a BYE and a CANCEL. Once the handler goes on, its decision
/// finds the final taken, and the waiting INVITEs reach the handler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_concurrency_limit_does_not_block_ack() {
    let _alone = FLOODING.lock().await;
    for transport in ["UDP", "TCP"] {
        for stack in [Stack::Limit, Stack::Buffered] {
            fill_and_go_on(transport, stack).await;
        }
    }
}

async fn fill_and_go_on(transport: &str, stack: Stack) {
    let context = format!("{transport} {stack:?}");
    // Two places for events other than the ends of attempts.
    let (ua, udp, tcp) = loaded(config().event_capacity(2));
    let (running, gate) = (Running::default(), Gate::new());
    let (decided, mut decisions) = mpsc::unbounded_channel();
    let handler = {
        let (running, gate) = (running.clone(), gate.clone());
        service_fn(move |invite: IncomingInvite| {
            let (running, gate, decided) =
                (running.clone(), gate.clone(), decided.clone());
            async move {
                let _running = running.enter();
                let call = invite.request().headers().get("Call-ID").unwrap();
                let call = call.as_str().to_owned();
                if call == "held" {
                    gate.passed().await;
                }
                let decision = match invite.try_accept(sdp()) {
                    Ok(accepted) => accepted.await,
                    Err(refused) => Err(refused.error()),
                };
                decided.send((call, decision)).unwrap();
                Ok::<(), Infallible>(())
            }
        })
    };
    let (not_ready, calls) = (Arc::default(), Arc::default());
    let service: BoxService<IncomingInvite, (), BoxError> = match stack {
        Stack::Limit => BoxService::new(
            ServiceBuilder::new()
                .concurrency_limit(1)
                .service(handler)
                .map_err(BoxError::from),
        ),
        Stack::Buffered => BoxService::new(
            ServiceBuilder::new()
                .buffer(1)
                .concurrency_limit(1)
                .service(handler),
        ),
    };
    let watched = Watched {
        inner: service,
        not_ready: Arc::clone(&not_ready),
        calls: Arc::clone(&calls),
    };
    let serving = Serving::start(ua, watched);
    let handle = serving.handle.clone();
    let mut peer = Wire::connect(transport, udp, tcp).await;
    let me = peer.address();

    // A call whose 2xx waits for its ACK, and an INVITE the handler holds.
    peer.send(&invite_over(transport, me, "callee")).await;
    let ok = answer_to(&mut peer, "SIP/2.0 200", "1 INVITE", "callee").await;
    let (call, session) =
        timeout(WAIT, decisions.recv()).await.unwrap().unwrap();
    assert_eq!(call, "callee");
    let session: Session = session.unwrap();
    peer.send(&invite_over(transport, me, "held")).await;
    let started = tokio::time::Instant::now();
    while calls.load(Ordering::SeqCst) < 2 || running.now() == 0 {
        assert!(
            started.elapsed() < WAIT,
            "{context}: the held INVITE in time"
        );
        sleep(Duration::from_millis(5)).await;
    }

    // More INVITEs until the UA has no room for another.
    let mut refused = None;
    for n in 0..8 {
        let call = format!("queued-{n}");
        peer.send(&invite_over(transport, me, &call)).await;
        let busy = answer_to(&mut peer, "SIP/2.0 503", "1 INVITE", &call);
        if timeout(Duration::from_millis(100), busy).await.is_ok() {
            refused = Some(n);
            break;
        }
    }
    let refused = refused.expect("a 503 once the event queue is full");
    let taken = calls.load(Ordering::SeqCst);
    let held_back = match stack {
        Stack::Limit => 2,
        Stack::Buffered => 4,
    };
    assert_eq!(taken, held_back, "{context}");
    assert!(not_ready.load(Ordering::SeqCst) > 0, "{context}");
    assert!(refused >= 1, "{context}: refused queued-{refused}");

    // The callee's side, all while the limit is full.
    answer_to(&mut peer, "SIP/2.0 200", "1 INVITE", "callee").await;
    timeout(WAIT, peer.acknowledge(&ok, "callee", 1)).await.unwrap();
    peer.send(&cancel_of(transport, me, "held")).await;
    let (mut cancelled, mut terminated) = (false, false);
    while !(cancelled && terminated) {
        let message = timeout(WAIT, next(&mut peer))
            .await
            .expect("the CANCEL's answers");
        if header(&message, "Call-ID") != ["held"] {
            continue;
        }
        match (message.split(' ').nth(1), header(&message, "CSeq")[..].first())
        {
            (Some("200"), Some(&"1 CANCEL")) => cancelled = true,
            (Some("487"), Some(&"1 INVITE")) => terminated = true,
            _ => {}
        }
    }
    peer.send(&in_dialog("BYE", transport, &ok, me, "callee", 2)).await;
    answer_to(&mut peer, "SIP/2.0 200", "2 BYE", "callee").await;
    let snapshot = handle.snapshot(&session).await.unwrap().unwrap();
    assert!(snapshot.end_reason.is_some(), "{context}: {snapshot:?}");

    // The caller's side, still while the limit is full.
    let mut far = Far::new(transport).await;
    let attempt = handle
        .try_invite(plan_to(&far.target(), "answered"))
        .unwrap()
        .await
        .unwrap();
    let request = far.recv_starting("INVITE").await;
    let contact = format!("sip:peer@{}", far.target());
    far.send(&answer(&request, "200", "far", &contact)).await;
    far.recv_starting("ACK").await;
    let calling = timeout(WAIT, async {
        loop {
            let snapshot =
                handle.attempt_snapshot(&attempt).await.unwrap().unwrap();
            if let Some(session) = snapshot.sessions.first() {
                break session.clone();
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let bye = handle.try_terminate(&calling).unwrap();
    let request = far.recv_starting("BYE").await;
    far.send(&ok_to(&request)).await;
    assert_eq!(timeout(WAIT, bye).await.unwrap(), Ok(()), "{context}");
    let ringing = handle
        .try_invite(plan_to(&far.target(), "ringing"))
        .unwrap()
        .await
        .unwrap();
    let request = far.recv_starting("INVITE").await;
    far.send(&reply_with(&request, 180, "far")).await;
    let cancel = handle.try_cancel(&ringing).unwrap();
    let cancelling = far.recv_starting("CANCEL").await;
    far.send(&reply_with(&cancelling, 200, "far")).await;
    far.send(&reply_with(&request, 487, "far")).await;
    assert_eq!(timeout(WAIT, cancel).await.unwrap(), Ok(CancelResult::Sent));

    // The limit was full all along.
    assert_eq!((running.now(), running.most()), (1, 1), "{context}");
    assert_eq!(calls.load(Ordering::SeqCst), taken, "{context}");

    gate.open();
    let (call, late) = timeout(WAIT, decisions.recv()).await.unwrap().unwrap();
    assert_eq!(call, "held", "{context}");
    assert!(
        matches!(late, Err(Error::AlreadyFinalized | Error::StaleDecision)),
        "{context}: {late:?}"
    );
    let (call, decision) =
        timeout(WAIT, decisions.recv()).await.unwrap().unwrap();
    assert_eq!(call, "queued-0", "{context}");
    assert!(decision.is_ok(), "{context}: {decision:?}");
    assert_eq!(running.most(), 1, "{context}");

    serving.driver.abort();
    timeout(WAIT, serving.adapter).await.unwrap().unwrap();
}
