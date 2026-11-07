/*!
UDP buffering and local send completion for one endpoint socket.
*/

use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};

use super::reply::{Completion, ReplyError};
use crate::transport::{udp, Flow, WriteLimits};

/// The UDP socket, its read buffer, and the datagrams waiting for it to be
/// writable.
pub(super) struct Datagram {
    socket: udp::Socket,
    buf: BytesMut,
    backlog: VecDeque<(Bytes, Flow, Option<Completion>)>,
    limits: WriteLimits,
    queued_bytes: usize,
}

impl Datagram {
    pub(super) fn new(socket: udp::Socket, limits: WriteLimits) -> Datagram {
        Datagram {
            socket,
            buf: BytesMut::new(),
            backlog: VecDeque::new(),
            limits,
            queued_bytes: 0,
        }
    }

    fn admit(&self, bytes: usize) -> io::Result<()> {
        if self.backlog.len() >= self.limits.messages
            || self
                .queued_bytes
                .checked_add(bytes)
                .map_or(true, |total| total > self.limits.bytes)
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
        self.backlog.push_back((bytes, flow, None));
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

    pub(super) fn submit(
        &mut self,
        bytes: Bytes,
        flow: Flow,
        completion: Completion,
    ) {
        let before = self.backlog.len();

        match self.send(&bytes, &flow) {
            Ok(()) if self.backlog.len() > before => {
                self.backlog.back_mut().expect("just enqueued").2 =
                    Some(completion);
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

    fn finish_front(&mut self, result: io::Result<()>) {
        if let Some((bytes, _, completion)) = self.backlog.pop_front() {
            self.queued_bytes -= bytes.len();
            drop(bytes);
            if let Some(completion) = completion {
                completion.finish(result.map_err(ReplyError::Transport));
            }
        }
    }

    /// Sends what waits, as far as the socket takes it.
    pub(super) fn poll_flush(&mut self, cx: &mut Context<'_>) {
        while let Some((bytes, flow, _)) = self.backlog.front() {
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
    }
}

// These queue tests use sockets, which Miri cannot provide.
#[cfg(all(test, not(miri)))]
mod tests {
    use std::{
        future::{poll_fn, Future},
        sync::Arc,
        time::Duration,
    };

    use tokio::{
        net::UdpSocket,
        sync::{mpsc, Semaphore},
        time::timeout,
    };

    use super::*;
    use crate::transport::budget::Budget;
    use crate::{
        endpoint::{
            driver::Command,
            reply::ReplyRoute,
            tests::{
                route_request, route_response, udp_reply_link, REPLY_LOCAL,
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
