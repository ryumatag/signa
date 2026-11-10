/*!
UDP buffering and local send completion for one endpoint socket.
*/

use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use tokio::sync::oneshot;

use super::{
    reply::{Completion, ReplyError},
    server::{Shared, WriteObservation},
};
use crate::transport::{Flow, WriteLimits, udp};

/// The UDP socket, its read buffer, and the datagrams waiting for it to be
/// writable.
pub(super) struct Datagram {
    socket: udp::Socket,
    buf: BytesMut,
    backlog: VecDeque<Queued>,
    limits: WriteLimits,
    queued_bytes: usize,
    failures: VecDeque<Arc<Shared>>,
}

/// A datagram waiting for the socket.
struct Queued {
    bytes: Bytes,
    flow: Flow,
    outcome: Outcome,
}

/// Who learns how a queued write ended.
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

impl Datagram {
    pub(super) fn new(socket: udp::Socket, limits: WriteLimits) -> Datagram {
        Datagram {
            socket,
            buf: BytesMut::new(),
            backlog: VecDeque::new(),
            limits,
            queued_bytes: 0,
            failures: VecDeque::new(),
        }
    }

    // Only the driver owns this quota. It does not await between checking
    // admission and committing the server response, so capacity cannot race.
    pub(super) fn admit_response(&self, bytes: usize) -> io::Result<()> {
        self.admit(bytes)
    }

    fn admit(&self, bytes: usize) -> io::Result<()> {
        self.admit_with_limits(bytes, self.limits)
    }

    fn admit_with_limits(
        &self,
        bytes: usize,
        limits: WriteLimits,
    ) -> io::Result<()> {
        if self.backlog.len() >= limits.messages
            || self
                .queued_bytes
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

    // Only the driver owns this queue, and a socket send attempt is
    // synchronous. Unlike TCP batches, no work leaves it while still pending.
    fn enqueue(&mut self, bytes: Bytes, flow: Flow) -> io::Result<()> {
        self.admit(bytes.len())?;
        let len = bytes.len();
        self.backlog.push_back(Queued {
            bytes,
            flow,
            outcome: Outcome::Unobserved,
        });
        self.queued_bytes += len;

        Ok(())
    }

    pub(super) fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr()
    }

    pub(super) fn is_idle(&self) -> bool {
        self.backlog.is_empty()
    }

    pub(super) fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(Bytes, Flow)>> {
        self.socket.poll_recv(cx, &mut self.buf)
    }

    /// Sends `bytes` on `flow` now, or queues it when the socket is not
    /// writable at the moment.
    ///
    /// A datagram that waits and then fails is dropped. UDP loses datagrams
    /// anyway, and the transactions retransmit over it.
    pub(super) fn send(
        &mut self,
        bytes: &Bytes,
        flow: &Flow,
    ) -> io::Result<()> {
        if self.backlog.is_empty() {
            self.admit(bytes.len())?;
            match self.socket.try_send(bytes, flow) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
        }
        self.enqueue(bytes.clone(), *flow)
    }

    pub(super) fn send_request(
        &mut self,
        bytes: &Bytes,
        flow: &Flow,
    ) -> io::Result<()> {
        self.admit_with_limits(
            bytes.len(),
            crate::transport::budget::request_limits(self.limits),
        )?;
        self.send(bytes, flow)
    }

    /// Sends a client request, returning a receipt when it has to wait for
    /// the socket.
    pub(super) fn submit_client(
        &mut self,
        bytes: &Bytes,
        flow: &Flow,
        initial: bool,
    ) -> io::Result<Option<oneshot::Receiver<io::Result<()>>>> {
        let before = self.backlog.len();
        if initial {
            self.send_request(bytes, flow)?;
        } else {
            self.send(bytes, flow)?;
        }
        if self.backlog.len() == before {
            return Ok(None);
        }

        let (done, receipt) = oneshot::channel();
        self.backlog.back_mut().expect("just enqueued").outcome =
            Outcome::Client(done);
        Ok(Some(receipt))
    }

    pub(super) fn submit(
        &mut self,
        bytes: Bytes,
        flow: Flow,
        completion: Completion,
    ) {
        let before = self.backlog.len();

        match self.send(&bytes, &flow) {
            Ok(()) if self.backlog.len() > before => {
                self.backlog.back_mut().expect("just enqueued").outcome =
                    Outcome::Reply(completion);
            }
            result => {
                drop(bytes);
                completion.finish(result.map_err(|error| {
                    if error.kind() == io::ErrorKind::WouldBlock {
                        ReplyError::Busy
                    } else {
                        ReplyError::Transport(error)
                    }
                }));
            }
        }
    }

    pub(super) fn take_failure(&mut self) -> Option<Arc<Shared>> {
        self.failures.pop_front()
    }

    /// Commits the driver's earlier admission check without yielding between
    /// phases. No other task owns this queue or can change its quota.
    pub(super) fn send_admitted(
        &mut self,
        bytes: Bytes,
        flow: Flow,
        observation: WriteObservation,
    ) -> bool {
        debug_assert!(self.admit(bytes.len()).is_ok());
        if self.backlog.is_empty() {
            match self.socket.try_send(&bytes, &flow) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => {
                    let success = result.is_ok();
                    observation.complete(result);
                    return success;
                }
            }
        }

        self.queued_bytes += bytes.len();
        self.backlog.push_back(Queued {
            bytes,
            flow,
            outcome: Outcome::Server(observation),
        });

        true
    }

    fn finish_front(&mut self, result: io::Result<()>) {
        let Some(Queued { bytes, outcome, .. }) = self.backlog.pop_front()
        else {
            return;
        };
        self.queued_bytes -= bytes.len();
        drop(bytes);

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

    /// Sends what waits, as far as the socket takes it.
    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) {
        for _ in 0..32 {
            let Some(Queued { bytes, flow, .. }) = self.backlog.front() else {
                return;
            };

            match self.socket.poll_send_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => {
                    self.finish_front(Err(error));
                    continue;
                }
                Poll::Pending => return,
            }

            match self.socket.try_send(bytes, flow) {
                // Readiness is cleared, and the next poll waits for it.
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                result => self.finish_front(result),
            }
        }

        if !self.backlog.is_empty() {
            cx.waker().wake_by_ref();
        }
    }
}

// These queue tests use sockets, which Miri cannot provide.
#[cfg(all(test, not(miri)))]
mod tests {
    use std::{
        future::{Future, poll_fn},
        sync::Arc,
        time::Duration,
    };

    use tokio::{
        net::UdpSocket,
        sync::{Semaphore, mpsc},
        time::timeout,
    };

    use super::*;
    use crate::transport::budget::Budget;
    use crate::{
        endpoint::{
            driver::Command,
            reply::ReplyRoute,
            tests::{
                REPLY_LOCAL, route_request, route_response, udp_reply_link,
            },
        },
        message::response::Response,
    };

    struct Fixture {
        datagram: Datagram,
        route: ReplyRoute,
        response: Response<Bytes>,
        commands: mpsc::UnboundedReceiver<Command>,
        capacity: Arc<Semaphore>,
    }

    fn fixture(remote: SocketAddr) -> Fixture {
        let socket = udp::Socket::bind(REPLY_LOCAL).unwrap();
        let link = udp_reply_link(socket.local_addr(), remote);
        let request = route_request(
            "SIP/2.0/UDP example.com:9;branch=z9hG4bKroute;rport",
        );
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

        Fixture {
            datagram: Datagram::new(
                socket,
                WriteLimits { messages: 1024, ..WriteLimits::default() },
            ),
            route,
            response,
            commands: receiver,
            capacity,
        }
    }

    #[tokio::test]
    async fn queued_client_write_failure_reaches_its_receipt() {
        let mut fixture = fixture("127.0.0.1:9".parse().unwrap());
        let flow = udp_reply_link(
            fixture.datagram.local_addr(),
            "127.0.0.1:9".parse().unwrap(),
        )
        .flow;
        fixture.datagram.enqueue(Bytes::from_static(b"queued"), flow).unwrap();

        let receipt = fixture
            .datagram
            .submit_client(&Bytes::from_static(b"request"), &flow, true)
            .unwrap()
            .unwrap();
        fixture.datagram.finish_front(Ok(()));
        fixture.datagram.finish_front(Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "test failure",
        )));

        assert_eq!(
            receipt.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
        assert!(fixture.datagram.is_idle());
        assert_eq!(fixture.datagram.queued_bytes, 0);
    }

    #[tokio::test]
    async fn new_requests_leave_udp_capacity_for_transaction_output() {
        let Fixture { mut datagram, .. } =
            fixture("127.0.0.1:9".parse().unwrap());
        datagram.limits = WriteLimits { messages: 4, bytes: 8 };
        let flow = udp_reply_link(
            datagram.local_addr(),
            "127.0.0.1:9".parse().unwrap(),
        )
        .flow;
        datagram.enqueue(Bytes::from_static(b"123456"), flow).unwrap();
        assert_eq!(
            datagram
                .send_request(&Bytes::from_static(b"7"), &flow)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        datagram.send(&Bytes::from_static(b"78"), &flow).unwrap();
        datagram.send_request(&Bytes::new(), &flow).unwrap_err();
        datagram.send(&Bytes::new(), &flow).unwrap();
        datagram.send(&Bytes::new(), &flow).unwrap();
        assert_eq!(datagram.backlog.len(), 4);
    }

    #[tokio::test]
    async fn queued_datagrams_keep_count_and_bytes_until_the_send_attempt() {
        let Fixture { mut datagram, .. } =
            fixture("127.0.0.1:9".parse().unwrap());
        datagram.limits = WriteLimits { messages: 2, bytes: 3 };
        let flow = udp_reply_link(
            datagram.local_addr(),
            "127.0.0.1:9".parse().unwrap(),
        )
        .flow;
        datagram.enqueue(Bytes::from_static(b"abc"), flow).unwrap();

        assert_eq!(
            datagram
                .send(&Bytes::from_static(b"d"), &flow)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        datagram.send(&Bytes::new(), &flow).unwrap();
        assert_eq!(
            datagram.send(&Bytes::new(), &flow).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        datagram.finish_front(Err(io::Error::from_raw_os_error(5)));
        datagram.send(&Bytes::from_static(b"def"), &flow).unwrap();

        assert_eq!(datagram.backlog.len(), 2);
        datagram.finish_front(Ok(()));
        datagram.finish_front(Ok(()));
        assert_eq!(datagram.queued_bytes, 0);
        assert!(datagram.admit(3).is_ok());
    }

    #[tokio::test]
    async fn even_an_immediate_datagram_must_fit_its_budget() {
        let Fixture { mut datagram, .. } =
            fixture("127.0.0.1:9".parse().unwrap());
        datagram.limits = WriteLimits { messages: 1, bytes: 2 };
        let flow = udp_reply_link(
            datagram.local_addr(),
            "127.0.0.1:9".parse().unwrap(),
        )
        .flow;

        assert_eq!(
            datagram
                .send(&Bytes::from_static(b"abc"), &flow)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );

        assert!(datagram.backlog.is_empty());
        assert!(datagram.admit(2).is_ok());
    }

    #[tokio::test]
    async fn a_queued_udp_error_is_observed_with_its_io_source() {
        let Fixture { mut datagram, route, response, mut commands, capacity } =
            fixture("127.0.0.1:9".parse().unwrap());
        let flow = udp_reply_link(
            datagram.local_addr(),
            "127.0.0.1:9".parse().unwrap(),
        )
        .flow;

        // Keep the reply queued without relying on kernel send-buffer pressure.
        datagram.enqueue(Bytes::new(), flow).unwrap();
        let mut send = std::pin::pin!(route.send(response));
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
        datagram.submit(bytes, link.flow, completion);

        assert_eq!(capacity.available_permits(), 0);
        datagram.finish_front(Ok(()));
        datagram.finish_front(Err(io::Error::from_raw_os_error(5)));

        let Err(ReplyError::Transport(error)) = send.await else {
            panic!("expected datagram error");
        };

        assert_eq!(error.raw_os_error(), Some(5));
        assert_eq!(capacity.available_permits(), 1);
        assert!(datagram.is_idle());
    }

    #[tokio::test]
    async fn queued_reply_survives_a_dropped_waiter() {
        let peer = UdpSocket::bind(REPLY_LOCAL).await.unwrap();
        let Fixture { mut datagram, route, response, mut commands, capacity } =
            fixture(peer.local_addr().unwrap());
        let flow =
            udp_reply_link(datagram.local_addr(), peer.local_addr().unwrap())
                .flow;
        let expected = response.to_bytes();

        datagram.enqueue(Bytes::from_static(b"first"), flow).unwrap();

        {
            let mut send = std::pin::pin!(route.send(response));
            poll_fn(|cx| {
                assert!(send.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }

        let Command::Reply { link, bytes, completion } =
            commands.try_recv().unwrap()
        else {
            panic!("expected reply command");
        };
        datagram.submit(bytes, link.flow, completion);

        assert_eq!(datagram.backlog.len(), 2);
        assert_eq!(capacity.available_permits(), 0);

        timeout(
            Duration::from_secs(1),
            poll_fn(|cx| {
                datagram.poll_flush(cx);
                if datagram.is_idle() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }),
        )
        .await
        .unwrap();

        assert_eq!(capacity.available_permits(), 1);

        let mut buf = [0; 2048];
        let (n, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"first");

        let (n, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], expected.as_ref());
    }
}
