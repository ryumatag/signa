/*!
The endpoint's side of its UDP backend.

[`Port`] owns the [`DatagramIo`] backend and keeps what the contract leaves to
the endpoint: write admission, the writes the backend has not accepted yet, the
writes it accepted but has not completed, and who learns how each one ended.
A write counts against the UDP write limits from admission to completion.

Writes go to the backend in [`WriteId`] order. A new write is offered at once
when nothing waits before it, with a waker that does nothing, and its
completion is collected in the same call. The built-in socket finishes both
there, so a send that the kernel takes costs no queueing and never enters the
table of writes in flight. A write the backend cannot take yet waits in the
backlog, and one it took without completing waits in that table.

The noop waker is safe because every call that starts a write runs while the
driver handles an event, and the driver polls each of its sources before it
waits. That includes [`Port::poll_flush`], which offers the backlog and
collects completions with the driver's waker whenever either has something,
and so replaces any waker the immediate attempt left with the backend.
*/

use std::{
    collections::{BTreeMap, VecDeque},
    io, mem,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll, Waker, ready},
};

use bytes::Bytes;
use tokio::sync::oneshot;

use super::{
    driver::{ReceptionCounters, increment},
    path::canonical,
    reply::{Completion, ReplyError},
    routing::Link,
    server::{Shared, WriteObservation},
};
use crate::transport::{
    Flow, Transport, WriteLimits,
    datagram::{
        DatagramIo, DatagramWrite, Path, RecvError, Submit, TransportContext,
        WriteId,
    },
};

/// How many writes, completions or datagrams one poll handles before it lets
/// the driver turn to its other sources.
const BATCH: usize = 32;

/// The UDP backend and the writes in its hands.
pub(super) struct Port {
    io: Box<dyn DatagramIo>,
    local: SocketAddr,
    max_payload: usize,
    limits: WriteLimits,
    /// Writes the backend has not accepted yet, oldest first.
    backlog: VecDeque<Queued>,
    /// Accepted writes waiting for their completion. A map rather than a
    /// queue, since a backend may complete them in any order, and one that
    /// never completes must not hold the entries of those after it.
    in_flight: BTreeMap<WriteId, InFlight>,
    /// Writes in either place, and their payload bytes. A write that
    /// [`Port::start`] is collecting counts too.
    writes: usize,
    bytes: usize,
    next_id: u64,
    /// The accepted write whose completion [`Port::start`] is collecting,
    /// with its length, and its result once it is in.
    awaited: Option<(WriteId, usize)>,
    awaited_result: Option<io::Result<()>>,
    failures: VecDeque<Arc<Shared>>,
    counters: Arc<ReceptionCounters>,
    /// Set when shutdown lost a write: one the backend never took, one it
    /// failed while closing, or one it left unreported.
    lost: bool,
}

/// A write waiting for the backend to accept it.
struct Queued {
    write: DatagramWrite,
    outcome: Outcome,
}

/// An accepted write waiting for its completion.
struct InFlight {
    len: usize,
    outcome: Outcome,
}

/// Who learns how a write ended.
enum Outcome {
    /// A plain send, such as a retransmission, which reports nothing.
    Unobserved,
    /// A one-shot reply through a route.
    Reply(Completion),
    /// A response submitted to a server transaction.
    Server(WriteObservation),
    /// A client request whose failure ends its transaction.
    Client(oneshot::Sender<io::Result<()>>),
}

/// How a write went when [`Port::start`] returned.
enum Started {
    /// It ended, or was never admitted.
    Done(io::Result<()>),
    /// It waits, in the backlog or for its completion.
    Waiting(WriteId),
}

impl Port {
    pub(super) fn new(
        io: Box<dyn DatagramIo>,
        limits: WriteLimits,
        counters: Arc<ReceptionCounters>,
    ) -> Port {
        let local = io.local_addr();
        let max_payload = io.capabilities().max_payload;
        Port {
            io,
            local,
            max_payload,
            limits,
            backlog: VecDeque::new(),
            in_flight: BTreeMap::new(),
            writes: 0,
            bytes: 0,
            next_id: 0,
            awaited: None,
            awaited_result: None,
            failures: VecDeque::new(),
            counters,
            lost: false,
        }
    }

    pub(super) fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Returns `true` when no write is queued or outstanding.
    pub(super) fn is_idle(&self) -> bool {
        self.writes == 0
    }

    // Only the driver owns this quota. It does not await between checking
    // admission and committing the server response, so capacity cannot race.
    pub(super) fn admit_response(&self, bytes: usize) -> io::Result<()> {
        self.admit(bytes, self.limits)
    }

    fn admit(&self, bytes: usize, limits: WriteLimits) -> io::Result<()> {
        if self.writes >= limits.messages
            || self
                .bytes
                .checked_add(bytes)
                .is_none_or(|total| total > limits.bytes)
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the UDP write budget is full",
            ));
        }

        Ok(())
    }

    /// Admits a write and offers it to the backend, unless earlier writes
    /// still wait for it.
    fn start(
        &mut self,
        bytes: Bytes,
        link: &Link,
        limits: WriteLimits,
    ) -> Started {
        let len = bytes.len();
        if len > self.max_payload {
            return Started::Done(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the datagram is larger than the UDP backend sends",
            )));
        }
        if let Err(error) = self.admit(len, limits) {
            return Started::Done(Err(error));
        }

        let id = WriteId::new(self.next_id);
        self.next_id += 1;
        self.writes += 1;
        self.bytes += len;
        // Cloning the path is a reference count, and only for a backend that
        // gave context. The socket's links have none.
        let write = DatagramWrite::new(
            id,
            bytes,
            link.flow.local,
            link.flow.remote,
            link.path.clone(),
        );
        if !self.backlog.is_empty() {
            self.backlog
                .push_back(Queued { write, outcome: Outcome::Unobserved });
            return Started::Waiting(id);
        }

        let mut cx = Context::from_waker(Waker::noop());
        match self.io.poll_submit(&mut cx, write) {
            Submit::Accepted => {
                self.awaited = Some((id, len));
                self.collect(&mut cx);
                if let Some(result) = self.awaited_result.take() {
                    return Started::Done(result);
                }
                self.awaited = None;
                self.in_flight.insert(
                    id,
                    InFlight { len, outcome: Outcome::Unobserved },
                );
                Started::Waiting(id)
            }
            Submit::Pending(write) => {
                self.backlog
                    .push_back(Queued { write, outcome: Outcome::Unobserved });
                Started::Waiting(id)
            }
            Submit::Rejected(write, error) => {
                drop(write);
                self.release(len);
                Started::Done(Err(error))
            }
        }
    }

    /// Names who learns how a waiting write ends. It is the last write
    /// [`Port::start`] queued, or one in flight.
    fn attach(&mut self, id: WriteId, outcome: Outcome) {
        if let Some(queued) = self.backlog.back_mut() {
            if queued.write.id() == id {
                queued.outcome = outcome;
                return;
            }
        }
        self.in_flight
            .get_mut(&id)
            .expect("a waiting write is queued or in flight")
            .outcome = outcome;
    }

    fn release(&mut self, len: usize) {
        self.writes -= 1;
        self.bytes -= len;
    }

    /// Sends `bytes` on `link`, or queues it until the backend takes it.
    ///
    /// Only an error known now is returned. A write that waits and then fails
    /// is dropped. UDP loses datagrams anyway, and the transactions
    /// retransmit over it.
    pub(super) fn send(
        &mut self,
        bytes: &Bytes,
        link: &Link,
    ) -> io::Result<()> {
        match self.start(bytes.clone(), link, self.limits) {
            Started::Done(result) => result,
            Started::Waiting(_) => Ok(()),
        }
    }

    /// Sends a new request as [`Port::send`] does, within the smaller budget
    /// that leaves room for transaction output.
    pub(super) fn send_request(
        &mut self,
        bytes: &Bytes,
        link: &Link,
    ) -> io::Result<()> {
        let limits = crate::transport::budget::request_limits(self.limits);
        match self.start(bytes.clone(), link, limits) {
            Started::Done(result) => result,
            Started::Waiting(_) => Ok(()),
        }
    }

    /// Sends a client request, returning a receipt when its outcome is not
    /// known yet.
    pub(super) fn submit_client(
        &mut self,
        bytes: &Bytes,
        link: &Link,
        initial: bool,
    ) -> io::Result<Option<oneshot::Receiver<io::Result<()>>>> {
        let limits = if initial {
            crate::transport::budget::request_limits(self.limits)
        } else {
            self.limits
        };
        match self.start(bytes.clone(), link, limits) {
            Started::Done(result) => result.map(|()| None),
            Started::Waiting(id) => {
                let (done, receipt) = oneshot::channel();
                self.attach(id, Outcome::Client(done));
                Ok(Some(receipt))
            }
        }
    }

    /// Sends a one-shot reply, which `completion` reports.
    pub(super) fn submit(
        &mut self,
        bytes: Bytes,
        link: &Link,
        completion: Completion,
    ) {
        match self.start(bytes, link, self.limits) {
            Started::Done(result) => {
                completion.finish(result.map_err(|error| {
                    if error.kind() == io::ErrorKind::WouldBlock {
                        ReplyError::Busy
                    } else {
                        ReplyError::Transport(error)
                    }
                }));
            }
            Started::Waiting(id) => {
                self.attach(id, Outcome::Reply(completion))
            }
        }
    }

    /// Commits the driver's earlier admission check without yielding between
    /// phases. No other task owns this queue or can change its quota.
    ///
    /// Returns `false` when the write has already failed, which `observation`
    /// has seen. A later failure goes to [`Port::take_failure`].
    pub(super) fn send_admitted(
        &mut self,
        bytes: Bytes,
        link: &Link,
        observation: WriteObservation,
    ) -> bool {
        debug_assert!(self.admit_response(bytes.len()).is_ok());
        match self.start(bytes, link, self.limits) {
            Started::Done(result) => {
                let success = result.is_ok();
                observation.complete(result);
                success
            }
            Started::Waiting(id) => {
                self.attach(id, Outcome::Server(observation));
                true
            }
        }
    }

    /// The next server transaction whose waiting write failed.
    pub(super) fn take_failure(&mut self) -> Option<Arc<Shared>> {
        self.failures.pop_front()
    }

    /// Offers what waits to the backend, as far as it takes it, and collects
    /// completions.
    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) {
        let mut more = false;
        for round in 0..=BATCH {
            let Some(Queued { write, outcome }) = self.backlog.pop_front()
            else {
                break;
            };
            if round == BATCH {
                self.backlog.push_front(Queued { write, outcome });
                more = true;
                break;
            }

            let id = write.id();
            let len = write.payload().len();
            match self.io.poll_submit(cx, write) {
                Submit::Accepted => {
                    self.in_flight.insert(id, InFlight { len, outcome });
                }
                Submit::Pending(write) => {
                    self.backlog.push_front(Queued { write, outcome });
                    break;
                }
                Submit::Rejected(write, error) => {
                    drop(write);
                    self.release(len);
                    self.finish(outcome, Err(error));
                }
            }
        }

        if self.collect(cx) || more {
            cx.waker().wake_by_ref();
        }
    }

    /// Returns `true` while an accepted write waits for its completion.
    fn awaits_completion(&self) -> bool {
        self.awaited.is_some() || !self.in_flight.is_empty()
    }

    /// Collects completions until the backend has none ready. Returns `true`
    /// if it stopped at the batch limit with more possibly ready.
    fn collect(&mut self, cx: &mut Context<'_>) -> bool {
        for _ in 0..BATCH {
            if !self.awaits_completion() {
                return false;
            }
            match self.io.poll_complete(cx) {
                Poll::Ready((id, result)) => self.complete(id, result),
                Poll::Pending => return false,
            }
        }

        self.awaits_completion()
    }

    /// Ends an accepted write. An ID the backend never had, or reported
    /// before, is ignored rather than trusted.
    fn complete(&mut self, id: WriteId, result: io::Result<()>) {
        if let Some((awaited, len)) = self.awaited {
            if awaited == id {
                self.awaited = None;
                self.release(len);
                self.awaited_result = Some(result);
                return;
            }
        }
        let Some(InFlight { len, outcome }) = self.in_flight.remove(&id)
        else {
            return;
        };
        self.release(len);
        self.finish(outcome, result);
    }

    fn finish(&mut self, outcome: Outcome, result: io::Result<()>) {
        match outcome {
            Outcome::Unobserved => {}
            Outcome::Reply(completion) => {
                completion.finish(result.map_err(ReplyError::Transport));
            }
            Outcome::Server(observation) => {
                if result.is_err() {
                    self.failures.push_back(observation.shared().clone());
                }
                observation.complete(result);
            }
            Outcome::Client(receipt) => {
                let _ = receipt.send(result);
            }
        }
    }

    /// Polls for the next datagram, with the flow it arrived on and the
    /// backend's context.
    ///
    /// The context is the backend's own bytes, which may slice a capture
    /// buffer. The driver copies it where it keeps it, see `path::retain`.
    ///
    /// A truncated datagram and a receive error are counted and discarded. An
    /// error also yields to the driver's other sources, so that a backend
    /// failing over and over cannot starve them.
    pub(super) fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<(Bytes, Flow, TransportContext)> {
        for _ in 0..BATCH {
            match ready!(self.io.poll_recv(cx)) {
                Ok(datagram) => {
                    let (payload, source, destination, context) =
                        datagram.into_parts();
                    // An IPv4 peer is named in its own form, as a Via names
                    // it, whichever backend reported it. The socket already
                    // does, and for it this is a match on the family.
                    let flow = Flow {
                        transport: Transport::Udp,
                        local: canonical(destination),
                        remote: canonical(source),
                    };
                    return Poll::Ready((payload, flow, context));
                }
                Err(RecvError::Truncated) => {
                    increment(&self.counters.truncated_datagrams);
                }
                Err(RecvError::Io(_)) => {
                    increment(&self.counters.receive_errors);
                    break;
                }
            }
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// Asks the backend whether it can send along `path`, a prepared one.
    pub(super) fn check_path(&mut self, path: &Path) -> io::Result<()> {
        let prepared = path.prepared.as_deref().expect("a prepared path");
        self.io.check_path(
            prepared.source,
            prepared.destination,
            &path.context,
        )
    }

    /// Offers the backlog and collects completions until no write is left,
    /// for a driver that has stopped but not reached its deadline.
    pub(super) fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.poll_flush(cx);
        if self.is_idle() { Poll::Ready(()) } else { Poll::Pending }
    }

    /// Drops the writes the backend has not accepted, at the shutdown
    /// deadline. Their waiters see the endpoint closed.
    pub(super) fn abort(&mut self) {
        for Queued { write, outcome } in mem::take(&mut self.backlog) {
            self.lost = true;
            self.release(write.payload().len());
            drop(outcome);
        }
    }

    /// Closes the backend once nothing more will be offered, then collects
    /// the outcomes it reported for its outstanding writes.
    ///
    /// A write the backend left unreported is dropped, and its waiter sees
    /// the endpoint closed.
    pub(super) fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        debug_assert!(self.backlog.is_empty(), "abort or drain first");
        ready!(self.io.poll_close(cx));

        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..=self.in_flight.len() {
            if self.in_flight.is_empty() {
                break;
            }
            match self.io.poll_complete(&mut cx) {
                Poll::Ready((id, result)) => {
                    if result.is_err() && self.in_flight.contains_key(&id) {
                        self.lost = true;
                    }
                    self.complete(id, result);
                }
                Poll::Pending => break,
            }
        }
        for (_, InFlight { len, outcome }) in mem::take(&mut self.in_flight) {
            self.lost = true;
            self.release(len);
            drop(outcome);
        }

        Poll::Ready(())
    }

    /// Returns `true` if shutdown lost a write. See [`Port::abort`] and
    /// [`Port::poll_close`].
    pub(super) fn lost(&self) -> bool {
        self.lost
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::{Future, poll_fn},
        sync::{Mutex, atomic::Ordering},
    };

    use tokio::sync::{Semaphore, mpsc};

    use super::*;
    use crate::{
        endpoint::{
            driver::Command,
            reply::ReplyRoute,
            tests::{REPLY_LOCAL, route_request, route_response},
        },
        message::response::Response,
        transport::{
            budget::Budget,
            datagram::{Capabilities, Datagram},
        },
    };

    const LOCAL: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        5060,
    );
    const PEER: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2)),
        5060,
    );
    const FLOW: Flow =
        Flow { transport: Transport::Udp, local: LOCAL, remote: PEER };
    const LINK: Link = Link { flow: FLOW, writer: None, path: None };

    /// What the scripted backend does with the next submission.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Mode {
        /// Accept and complete it at once, as the socket does.
        Complete,
        /// Accept it and complete it only when the test says.
        Accept,
        /// Hand it back as pending.
        Hold,
        /// Refuse it with an I/O error.
        Reject,
    }

    #[derive(Default)]
    struct State {
        mode: Option<Mode>,
        accepted: Vec<(WriteId, Bytes)>,
        completions: VecDeque<(WriteId, io::Result<()>)>,
        received: VecDeque<Result<Datagram, RecvError>>,
        closes: usize,
        /// What the backend reports for its outstanding writes on close.
        on_close: Vec<(WriteId, io::Result<()>)>,
        /// The wakers of the last pending submission and completion poll.
        submit_waker: Option<Waker>,
        complete_waker: Option<Waker>,
    }

    /// A backend the test drives through shared state.
    #[derive(Clone, Default)]
    struct Script(Arc<Mutex<State>>);

    impl Script {
        fn mode(&self, mode: Mode) {
            self.0.lock().unwrap().mode = Some(mode);
        }

        fn complete(&self, id: WriteId, result: io::Result<()>) {
            self.0.lock().unwrap().completions.push_back((id, result));
        }

        fn accepted(&self) -> Vec<WriteId> {
            self.0.lock().unwrap().accepted.iter().map(|(id, _)| *id).collect()
        }

        fn receive(&self, datagram: Result<Datagram, RecvError>) {
            self.0.lock().unwrap().received.push_back(datagram);
        }
    }

    impl DatagramIo for Script {
        fn local_addr(&self) -> SocketAddr {
            LOCAL
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities::new(1000)
        }

        fn poll_recv(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Datagram, RecvError>> {
            match self.0.lock().unwrap().received.pop_front() {
                Some(datagram) => Poll::Ready(datagram),
                None => Poll::Pending,
            }
        }

        fn poll_submit(
            &mut self,
            cx: &mut Context<'_>,
            write: DatagramWrite,
        ) -> Submit {
            let mut state = self.0.lock().unwrap();
            match state.mode.unwrap_or(Mode::Complete) {
                Mode::Complete => {
                    state.completions.push_back((write.id(), Ok(())));
                }
                Mode::Accept => {}
                Mode::Hold => {
                    state.submit_waker = Some(cx.waker().clone());
                    return Submit::Pending(write);
                }
                Mode::Reject => {
                    return Submit::Rejected(
                        write,
                        io::Error::from_raw_os_error(5),
                    );
                }
            }
            state.accepted.push((write.id(), write.into_payload()));
            Submit::Accepted
        }

        fn poll_complete(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<(WriteId, io::Result<()>)> {
            let mut state = self.0.lock().unwrap();
            match state.completions.pop_front() {
                Some(completion) => Poll::Ready(completion),
                None => {
                    state.complete_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        }

        fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<()> {
            let mut state = self.0.lock().unwrap();
            state.closes += 1;
            let on_close = mem::take(&mut state.on_close);
            state.completions.extend(on_close);
            Poll::Ready(())
        }
    }

    fn port(script: &Script, limits: WriteLimits) -> Port {
        Port::new(Box::new(script.clone()), limits, Arc::default())
    }

    fn flush(port: &mut Port) {
        port.poll_flush(&mut Context::from_waker(Waker::noop()));
    }

    /// A reply route whose `send` lands in `commands`, with one slot of
    /// one-shot capacity.
    fn route() -> (
        ReplyRoute,
        Response<Bytes>,
        mpsc::UnboundedReceiver<Command>,
        Arc<Semaphore>,
    ) {
        let request = route_request(
            "SIP/2.0/UDP example.com:9;branch=z9hG4bKroute;rport",
        );
        let link = crate::endpoint::tests::udp_reply_link(REPLY_LOCAL, PEER);
        let (commands, receiver) = mpsc::unbounded_channel();
        let capacity = Arc::new(Semaphore::new(1));
        let route = ReplyRoute::new(
            &request,
            link,
            commands,
            capacity.clone(),
            Budget::new(WriteLimits::default()),
        );
        let response = route_response(&request);

        (route, response, receiver, capacity)
    }

    /// Starts `route.send` and hands its command to the port.
    async fn submit_reply(
        port: &mut Port,
        send: std::pin::Pin<&mut impl Future<Output = Result<(), ReplyError>>>,
        commands: &mut mpsc::UnboundedReceiver<Command>,
    ) {
        let mut send = send;
        poll_fn(|cx| {
            assert!(send.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let Command::Reply { link, bytes, completion } =
            commands.try_recv().unwrap()
        else {
            panic!("expected reply command");
        };
        port.submit(bytes, &link, completion);
    }

    #[test]
    fn a_write_the_backend_finishes_at_once_needs_no_queue() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits::default());

        port.send(&Bytes::from_static(b"hello"), &LINK).unwrap();

        assert!(port.is_idle());
        assert_eq!(script.0.lock().unwrap().accepted[0].1, "hello");
    }

    #[test]
    fn a_held_write_waits_in_order_and_keeps_its_budget() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits { messages: 2, bytes: 10 });
        script.mode(Mode::Hold);

        port.send(&Bytes::from_static(b"first"), &LINK).unwrap();
        port.send(&Bytes::from_static(b"second"), &LINK).unwrap_err();
        port.send(&Bytes::from_static(b"two"), &LINK).unwrap();
        assert_eq!(
            port.send(&Bytes::new(), &LINK).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        script.mode(Mode::Accept);
        flush(&mut port);
        let accepted = script.accepted();
        assert_eq!(accepted.len(), 2);
        assert!(accepted[0] < accepted[1]);
        // Accepted is not complete. The budget holds until completion.
        assert!(port.admit_response(0).is_err());

        script.complete(accepted[1], Ok(()));
        flush(&mut port);
        assert_eq!(port.writes, 1);
        assert_eq!(port.bytes, 5);
        script.complete(accepted[0], Ok(()));
        flush(&mut port);
        assert!(port.is_idle());
        assert!(port.in_flight.is_empty());
    }

    #[test]
    fn new_requests_leave_udp_capacity_for_transaction_output() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits { messages: 4, bytes: 8 });
        script.mode(Mode::Hold);

        port.send(&Bytes::from_static(b"123456"), &LINK).unwrap();
        assert_eq!(
            port.send_request(&Bytes::from_static(b"7"), &LINK)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        port.send(&Bytes::from_static(b"78"), &LINK).unwrap();
        port.send_request(&Bytes::new(), &LINK).unwrap_err();
        port.send(&Bytes::new(), &LINK).unwrap();
        port.send(&Bytes::new(), &LINK).unwrap();

        assert_eq!(port.backlog.len(), 4);
    }

    #[test]
    fn even_an_immediate_datagram_must_fit_its_budget() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits { messages: 1, bytes: 2 });

        assert_eq!(
            port.send(&Bytes::from_static(b"abc"), &LINK).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        assert!(script.accepted().is_empty());
        assert!(port.admit_response(2).is_ok());
    }

    #[test]
    fn a_payload_over_the_backend_maximum_fails_before_submission() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits::default());

        let error = port.send(&Bytes::from(vec![0; 1001]), &LINK).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(script.accepted().is_empty());
        assert!(port.is_idle());
    }

    #[test]
    fn a_rejected_write_fails_now_and_frees_its_budget() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits { messages: 1, bytes: 8 });
        script.mode(Mode::Reject);

        let error = port.send(&Bytes::from_static(b"abc"), &LINK).unwrap_err();

        assert_eq!(error.raw_os_error(), Some(5));
        assert!(port.is_idle());
    }

    #[tokio::test]
    async fn queued_client_write_failure_reaches_its_receipt() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits::default());
        script.mode(Mode::Hold);

        let receipt = port
            .submit_client(&Bytes::from_static(b"request"), &LINK, true)
            .unwrap()
            .unwrap();
        script.mode(Mode::Accept);
        flush(&mut port);
        let id = script.accepted()[0];
        script.complete(
            id,
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused")),
        );
        flush(&mut port);

        assert_eq!(
            receipt.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
        assert!(port.is_idle());
        assert_eq!(port.bytes, 0);
    }

    #[test]
    fn an_immediate_client_write_needs_no_receipt() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits::default());

        let receipt = port
            .submit_client(&Bytes::from_static(b"request"), &LINK, true)
            .unwrap();

        assert!(receipt.is_none());
    }

    #[tokio::test]
    async fn a_rejected_queued_reply_reports_its_io_error() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits::default());
        let (route, response, mut commands, capacity) = route();
        script.mode(Mode::Hold);

        let mut send = std::pin::pin!(route.send(response));
        submit_reply(&mut port, send.as_mut(), &mut commands).await;
        assert_eq!(capacity.available_permits(), 0);
        script.mode(Mode::Reject);
        flush(&mut port);

        let Err(ReplyError::Transport(error)) = send.await else {
            panic!("expected datagram error");
        };
        assert_eq!(error.raw_os_error(), Some(5));
        assert_eq!(capacity.available_permits(), 1);
        assert!(port.is_idle());
    }

    #[tokio::test]
    async fn a_reply_waits_for_its_completion_not_its_acceptance() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits::default());
        let (route, response, mut commands, capacity) = route();
        script.mode(Mode::Accept);

        let mut send = std::pin::pin!(route.send(response));
        submit_reply(&mut port, send.as_mut(), &mut commands).await;
        poll_fn(|cx| {
            assert!(send.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(capacity.available_permits(), 0);

        script.complete(script.accepted()[0], Ok(()));
        flush(&mut port);

        send.await.unwrap();
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn queued_reply_survives_a_dropped_waiter() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits::default());
        let (route, response, mut commands, capacity) = route();
        let expected = response.to_bytes();
        script.mode(Mode::Hold);

        {
            let mut send = std::pin::pin!(route.send(response));
            submit_reply(&mut port, send.as_mut(), &mut commands).await;
        }
        assert_eq!(capacity.available_permits(), 0);
        script.mode(Mode::Complete);
        flush(&mut port);

        assert_eq!(script.0.lock().unwrap().accepted[0].1, expected);
        assert_eq!(capacity.available_permits(), 1);
        assert!(port.is_idle());
    }

    #[test]
    fn unknown_and_repeated_completions_are_ignored() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits::default());
        script.mode(Mode::Accept);
        port.send(&Bytes::from_static(b"abc"), &LINK).unwrap();
        let id = script.accepted()[0];

        script.complete(WriteId::new(99), Ok(()));
        script.complete(id, Ok(()));
        script.complete(id, Err(io::Error::from_raw_os_error(5)));
        flush(&mut port);

        assert!(port.is_idle());
    }

    #[test]
    fn abort_drops_held_writes_and_close_collects_the_rest() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits::default());
        script.mode(Mode::Accept);
        let accepted = port
            .submit_client(&Bytes::from_static(b"accepted"), &LINK, false)
            .unwrap()
            .unwrap();
        let unreported = port
            .submit_client(&Bytes::from_static(b"unreported"), &LINK, false)
            .unwrap()
            .unwrap();
        script.mode(Mode::Hold);
        let held = port
            .submit_client(&Bytes::from_static(b"held"), &LINK, false)
            .unwrap()
            .unwrap();
        script.0.lock().unwrap().on_close = vec![(
            script.accepted()[0],
            Err(io::Error::new(io::ErrorKind::Interrupted, "closed")),
        )];

        port.abort();
        assert!(held.blocking_recv().is_err());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(port.poll_close(&mut cx).is_ready());

        assert_eq!(script.0.lock().unwrap().closes, 1);
        assert_eq!(
            accepted.blocking_recv().unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(unreported.blocking_recv().is_err());
        assert!(port.is_idle());
        assert!(port.lost());
    }

    #[test]
    fn a_close_that_finishes_every_write_loses_nothing() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits::default());
        script.mode(Mode::Accept);
        port.send(&Bytes::from_static(b"accepted"), &LINK).unwrap();
        script.0.lock().unwrap().on_close =
            vec![(script.accepted()[0], Ok(()))];

        port.abort();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(port.poll_close(&mut cx).is_ready());

        assert!(port.is_idle());
        assert!(!port.lost());
    }

    // The entries of writes completed after one that never completes are
    // gone, so the table stays within the write limits.
    #[test]
    fn a_write_that_never_completes_holds_only_itself() {
        let script = Script::default();
        let mut port =
            port(&script, WriteLimits { messages: 1024, bytes: 1 << 20 });
        script.mode(Mode::Accept);
        for _ in 0..100 {
            port.send(&Bytes::from_static(b"abc"), &LINK).unwrap();
        }

        for id in script.accepted().into_iter().skip(1) {
            script.complete(id, Ok(()));
        }
        for _ in 0..4 {
            flush(&mut port);
        }

        assert_eq!(port.in_flight.len(), 1);
        assert_eq!((port.writes, port.bytes), (1, 3));
    }

    /// Counts its wakes.
    #[derive(Default)]
    struct Counter(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for Counter {
        fn wake(self: Arc<Counter>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    // `start` offers a write with a noop waker. The driver's next flush must
    // leave the backend with the driver's waker, both for a write it holds
    // and for one it took without completing.
    #[test]
    fn a_flush_replaces_the_noop_waker_of_an_immediate_attempt() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits::default());
        let waker = Waker::from(Arc::new(Counter::default()));
        let mut cx = Context::from_waker(&waker);

        script.mode(Mode::Hold);
        port.send(&Bytes::from_static(b"held"), &LINK).unwrap();
        assert!(
            !script
                .0
                .lock()
                .unwrap()
                .submit_waker
                .as_ref()
                .unwrap()
                .will_wake(&waker)
        );
        port.poll_flush(&mut cx);
        assert!(
            script
                .0
                .lock()
                .unwrap()
                .submit_waker
                .as_ref()
                .unwrap()
                .will_wake(&waker)
        );

        script.mode(Mode::Accept);
        port.poll_flush(&mut cx);
        port.send(&Bytes::from_static(b"accepted"), &LINK).unwrap();
        assert!(
            !script
                .0
                .lock()
                .unwrap()
                .complete_waker
                .as_ref()
                .unwrap()
                .will_wake(&waker)
        );
        port.poll_flush(&mut cx);
        assert!(
            script
                .0
                .lock()
                .unwrap()
                .complete_waker
                .as_ref()
                .unwrap()
                .will_wake(&waker)
        );
        assert_eq!(port.in_flight.len(), 2);
    }

    #[test]
    fn receive_discards_and_counts_what_is_not_a_whole_datagram() {
        let script = Script::default();
        let mut port = port(&script, WriteLimits::default());
        let mut cx = Context::from_waker(Waker::noop());
        script.receive(Err(RecvError::Truncated));
        script.receive(Ok(Datagram::new(
            Bytes::from_static(b"whole"),
            PEER,
            LOCAL,
        )));
        script.receive(Err(RecvError::Io(io::Error::from_raw_os_error(5))));

        let Poll::Ready((payload, flow, context)) = port.poll_recv(&mut cx)
        else {
            panic!("expected a datagram");
        };
        assert_eq!(payload, "whole");
        assert_eq!(flow, FLOW);
        assert!(context.is_empty());
        assert!(port.poll_recv(&mut cx).is_pending());
        assert!(port.poll_recv(&mut cx).is_pending());

        let counters = &port.counters;
        assert_eq!(counters.truncated_datagrams.load(Ordering::Relaxed), 1);
        assert_eq!(counters.receive_errors.load(Ordering::Relaxed), 1);
    }
}
