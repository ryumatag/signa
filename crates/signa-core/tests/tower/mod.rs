/*!
An external Tower adapter for signa's transaction-user API.

These modules see only signa's public API, as any crate built on it would.
They build the pieces of a Tower adapter and run them against real endpoints
on the loopback:

* `adapter`: `Exchange<R>`, the adapter's handler envelope, made by
  destructuring signa's `ServerRequest` and splitting its transaction.
  `Respond`, a local response-sender trait, implemented for signa's
  `Responder` by naming its `ResponseSubmission<'a>` future. Nothing is boxed
  and signa implements no trait for it. Two sender wrappers, `Observed` and
  `Counted`, applied by Tower layers, so a generic leaf handler submits
  through `Counted<Observed<Responder>>`.
* `dispatch`: a bounded dispatcher with separate ordinary and control lanes.
  It owns one instance of each service, polls readiness and calls on that
  instance, and spawns a handler only after it has room for it.
* `service`: the application, a leaf handler and its control service.

Nothing here is part of signa. signa has no Tower dependency of its own, and
`tower` is only a dev-dependency. This module holds the harness, an endpoint
with the services and a raw UAC. The tests check:

* `responses`: the wrappers see every response the TU submits, 1xx and every
  2xx, and keep watching after the first final. They do not see the 100
  Trying signa sends or the responses its transactions retransmit.
* `control`: readiness and call use the same service instance, which is not
  `Clone`. Handlers waiting for an ACK or blocked on readiness do not hold up
  ACK and CANCEL, which go through the control lane. Running handlers and
  buffered calls stay within their limits, and an ordinary request beyond
  them gets a 503.
* `lifetime`: a handler's future finishing is not the end of its
  transaction, and a Tower timeout drops a handler without cancelling
  anything in SIP.
*/

mod adapter;
mod control;
mod dispatch;
mod lifetime;
mod responses;
mod service;

use std::{
    fmt,
    net::SocketAddr,
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use bytes::Bytes;
use signa_core::{
    Request, Response,
    endpoint::{Endpoint, Responder, ServerEvent, ServerEvents},
    message::header::{CSEQ, Tag},
    transaction::Timers,
};
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc},
    task::JoinHandle,
    time::timeout,
};
use tower::{Layer, Service};

use crate::tower::{
    adapter::Exchange,
    dispatch::{Limits, Stats, dispatch},
    service::{Answer, Calls, ControlService, Gate, Usage},
};

fn reply(request: &Request<Bytes>, status: u16, tag: &Tag) -> Response<Bytes> {
    Response::reply_to(request)
        .status(status)
        .to_tag(tag.clone())
        .body(Bytes::new())
        .unwrap()
}

/// RFC 3261's timers with a T1 of 20 ms, so that Timer L is 1.28 s. Nothing
/// below depends on the length of a timer.
fn timers() -> Timers {
    Timers::builder()
        .t1(Duration::from_millis(20))
        .t2(Duration::from_millis(160))
        .t4(Duration::from_millis(200))
        .build()
        .unwrap()
}

struct Harness {
    endpoint: Endpoint,
    calls: Calls,
    gate: Arc<Gate>,
    usage: Arc<Usage>,
    release: Arc<Notify>,
    finished: mpsc::UnboundedReceiver<ServerEvents>,
    acks: Arc<AtomicUsize>,
}

impl Harness {
    /// Binds an endpoint and dispatches its events to `layers` around the
    /// leaf handler.
    fn start<L>(limits: Limits, layers: L) -> (Harness, JoinHandle<Stats>)
    where
        L: Layer<Answer>,
        L::Service:
            Service<Exchange<Responder>, Response = ()> + Send + 'static,
        <L::Service as Service<Exchange<Responder>>>::Future: Send + 'static,
        <L::Service as Service<Exchange<Responder>>>::Error:
            fmt::Debug + Send + 'static,
    {
        let (endpoint, incoming) = Endpoint::builder()
            .udp("127.0.0.1:0".parse().unwrap())
            .timers(timers())
            .bind()
            .unwrap();
        let calls = Calls::default();
        let gate = Arc::new(Gate::default());
        let usage = Arc::new(Usage::default());
        let release = Arc::new(Notify::new());
        let (finished_tx, finished) = mpsc::unbounded_channel();
        let acks = Arc::new(AtomicUsize::new(0));
        let leaf = Answer {
            ready: false,
            calls: calls.clone(),
            gate: gate.clone(),
            usage: usage.clone(),
            release: release.clone(),
            finished: finished_tx,
        };
        let control = ControlService {
            ready: false,
            calls: calls.clone(),
            acks: acks.clone(),
        };
        let dispatching = tokio::spawn(dispatch(
            incoming,
            layers.layer(leaf),
            control,
            limits,
        ));
        let harness =
            Harness { endpoint, calls, gate, usage, release, finished, acks };
        (harness, dispatching)
    }

    async fn uac(&self) -> Uac {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Uac { socket, server: self.endpoint.udp_addr().unwrap() }
    }
}

const LIMITS: Limits = Limits {
    handlers: 8,
    queued: 8,
    control_handlers: 8,
    control_queued: 8,
    rejections: 2,
};

struct Uac {
    socket: UdpSocket,
    server: SocketAddr,
}

impl Uac {
    /// A `method` request of the call `call`, with `branch`, as text.
    fn request(
        &self,
        method: &str,
        user: &str,
        call: &str,
        branch: &str,
        to_tag: Option<&str>,
    ) -> String {
        let local = self.socket.local_addr().unwrap();
        let to = match to_tag {
            Some(tag) => format!("<sip:{user}@example.com>;tag={tag}"),
            None => format!("<sip:{user}@example.com>"),
        };
        format!(
            "{method} sip:{user}@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP {local};branch=z9hG4bK{branch};rport\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: {to}\r\n\
             Call-ID: {call}\r\n\
             CSeq: 1 {method}\r\n\
             Content-Length: 0\r\n\r\n"
        )
    }

    async fn send(&self, message: &str) {
        self.socket.send_to(message.as_bytes(), self.server).await.unwrap();
    }

    /// The next response, or `None` after `wait` without one.
    async fn next(&self, wait: Duration) -> Option<Response<Bytes>> {
        let mut buf = vec![0; 65536];
        let (len, _) = timeout(wait, self.socket.recv_from(&mut buf))
            .await
            .ok()?
            .unwrap();
        Some(Response::from_bytes(&buf[..len]).unwrap())
    }

    async fn status(&self) -> u16 {
        let response =
            self.next(Duration::from_secs(2)).await.expect("a response");
        response.status().as_u16()
    }

    /// Receives until a response with `status` arrives, and returns the
    /// statuses before it.
    async fn until(&self, status: u16) -> Vec<u16> {
        let mut before = Vec::new();
        loop {
            match self.status().await {
                found if found == status => return before,
                other => before.push(other),
            }
        }
    }
}

fn cseq_method(response: &Response<Bytes>) -> &str {
    response
        .headers()
        .get(CSEQ)
        .unwrap()
        .as_str()
        .split_whitespace()
        .nth(1)
        .unwrap()
}

/// Waits for the end of a transaction's observation.
async fn observe_end(mut events: ServerEvents) {
    while let Some(event) = events.next().await {
        if let ServerEvent::Terminated = event {
            return;
        }
    }
}
