/*!
The in-memory packet wire the endpoints run over.
*/

use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::Bytes;
use signa_core::transport::datagram::{
    Capabilities, Datagram, DatagramIo, DatagramWrite, RecvError, Submit,
    TransportContext, WriteId, WriteOutcome, WritePath,
};
use tokio::{sync::Notify, time::timeout};

use crate::datagram::{ALTERNATE, LINK_LOCAL, LOCAL};

/// What the wire does with the next write.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Writes {
    /// Takes it and reports it written at once.
    #[default]
    Complete,
    /// Takes it and reports it only when the test finishes it.
    Delay,
    /// Takes it and reports that writing it failed.
    Fail,
    /// Cannot take it now.
    Hold,
    /// Refuses it when it is offered.
    Reject,
    /// Refuses it with `WouldBlock`, as a backend whose own queue is full.
    Busy,
}

/// One write the wire accepted.
#[derive(Clone, Debug)]
pub(crate) struct Sent {
    pub(crate) payload: Bytes,
    pub(crate) source: SocketAddr,
    pub(crate) destination: SocketAddr,
    pub(crate) path: Way,
}

/// What [`WritePath`] a write came with, with its context's bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Way {
    Default,
    Reply(Bytes),
    Prepared(Bytes),
}

impl Way {
    pub(crate) fn reply(context: &'static str) -> Way {
        Way::Reply(Bytes::from_static(context.as_bytes()))
    }

    pub(crate) fn prepared(context: &'static str) -> Way {
        Way::Prepared(Bytes::from_static(context.as_bytes()))
    }
}

#[derive(Default)]
pub(crate) struct State {
    inbound: VecDeque<Result<Datagram, RecvError>>,
    recv: Option<Waker>,
    writes: Writes,
    sent: Vec<Sent>,
    pub(crate) submit: Option<Waker>,
    completions: VecDeque<(WriteId, WriteOutcome)>,
    complete: Option<Waker>,
    pub(crate) delayed: VecDeque<WriteId>,
    closed: bool,
    /// Makes the close never finish, as a backend with a stuck writer task.
    pub(crate) stuck: bool,
    /// Path contexts the wire refuses to send on any more, as for a PPPoE
    /// session that has ended.
    stale: Vec<Bytes>,
    /// The address the wire names as its own, `LOCAL` unless set.
    local: Option<SocketAddr>,
    /// Writes refused in `Writes::Reject` or `Writes::Busy`.
    pub(crate) refused: usize,
}

#[derive(Clone, Default)]
pub(crate) struct Wire {
    pub(crate) state: Arc<Mutex<State>>,
    sent: Arc<Notify>,
}

impl Wire {
    /// A wire that names `local` as its own address.
    pub(crate) fn at(local: SocketAddr) -> Wire {
        let wire = Wire::default();
        wire.state.lock().unwrap().local = Some(local);
        wire
    }

    pub(crate) fn deliver(&self, datagram: Result<Datagram, RecvError>) {
        let mut state = self.state.lock().unwrap();
        state.inbound.push_back(datagram);
        if let Some(waker) = state.recv.take() {
            waker.wake();
        }
    }

    pub(crate) fn writes(&self, writes: Writes) {
        let mut state = self.state.lock().unwrap();
        state.writes = writes;
        if let Some(waker) = state.submit.take() {
            waker.wake();
        }
    }

    /// Reports the newest delayed write.
    pub(crate) fn finish_newest(&self, outcome: impl Into<WriteOutcome>) {
        let mut state = self.state.lock().unwrap();
        let id = state.delayed.pop_back().expect("a delayed write");
        state.completions.push_back((id, outcome.into()));
        if let Some(waker) = state.complete.take() {
            waker.wake();
        }
    }

    /// Reports the oldest delayed write.
    pub(crate) fn finish(&self, outcome: impl Into<WriteOutcome>) {
        let mut state = self.state.lock().unwrap();
        let id = state.delayed.pop_front().expect("a delayed write");
        state.completions.push_back((id, outcome.into()));
        if let Some(waker) = state.complete.take() {
            waker.wake();
        }
    }

    /// Waits until the wire has accepted `n` writes, and returns them.
    pub(crate) async fn sent(&self, n: usize) -> Vec<Sent> {
        self.until(|state| state.sent.len() >= n).await;
        self.state.lock().unwrap().sent.clone()
    }

    /// Waits until `done` holds of the wire, as a write is accepted, held or
    /// refused.
    pub(crate) async fn until(&self, done: impl Fn(&State) -> bool) {
        timeout(Duration::from_secs(2), async {
            loop {
                let notified = self.sent.notified();
                if done(&self.state.lock().unwrap()) {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("the wire within two seconds")
    }

    pub(crate) fn closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }

    pub(crate) fn stale(&self, context: &'static str) {
        let context = Bytes::from_static(context.as_bytes());
        self.state.lock().unwrap().stale.push(context);
    }

    /// The number of writes the wire has accepted so far.
    pub(crate) fn count(&self) -> usize {
        self.state.lock().unwrap().sent.len()
    }
}

impl DatagramIo for Wire {
    fn local_addr(&self) -> SocketAddr {
        self.state.lock().unwrap().local.unwrap_or(LOCAL)
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::new(1472)
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Datagram, RecvError>> {
        let mut state = self.state.lock().unwrap();
        match state.inbound.pop_front() {
            Some(datagram) => Poll::Ready(datagram),
            None => {
                state.recv = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn poll_submit(
        &mut self,
        cx: &mut Context<'_>,
        write: DatagramWrite,
    ) -> Submit {
        let mut state = self.state.lock().unwrap();
        let id = write.id();
        let path = match write.path() {
            WritePath::Default => Way::Default,
            WritePath::Reply(context) => {
                Way::Reply(context.as_bytes().clone())
            }
            WritePath::Prepared(context) => {
                Way::Prepared(context.as_bytes().clone())
            }
            _ => unreachable!("no other paths"),
        };
        if let Way::Prepared(context) = &path {
            if state.stale.contains(context) {
                return Submit::Rejected(
                    write,
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "session ended",
                    ),
                );
            }
        }
        match state.writes {
            Writes::Complete => {
                state.completions.push_back((id, WriteOutcome::Written));
            }
            Writes::Delay => state.delayed.push_back(id),
            Writes::Fail => state.completions.push_back((
                id,
                WriteOutcome::NotWritten(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "link down",
                )),
            )),
            Writes::Hold => {
                state.submit = Some(cx.waker().clone());
                self.sent.notify_waiters();
                return Submit::Pending(write);
            }
            Writes::Reject => {
                state.refused += 1;
                self.sent.notify_waiters();
                return Submit::Rejected(
                    write,
                    io::Error::new(io::ErrorKind::NotConnected, "refused"),
                );
            }
            Writes::Busy => {
                state.refused += 1;
                self.sent.notify_waiters();
                return Submit::Rejected(
                    write,
                    io::Error::new(io::ErrorKind::WouldBlock, "queue full"),
                );
            }
        }
        state.sent.push(Sent {
            source: write.source(),
            destination: write.destination(),
            path,
            payload: write.into_payload(),
        });
        self.sent.notify_waiters();

        Submit::Accepted
    }

    fn poll_complete(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<(WriteId, WriteOutcome)> {
        let mut state = self.state.lock().unwrap();
        match state.completions.pop_front() {
            Some(completion) => Poll::Ready(completion),
            None => {
                state.complete = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    // The wire may send from its own address, the alternate one or its
    // link-local one, with any context. Another source, or the link-local
    // address on another interface, is not this host's to use.
    fn check_path(
        &mut self,
        source: SocketAddr,
        _destination: SocketAddr,
        _context: &TransportContext,
    ) -> io::Result<()> {
        if [LOCAL, ALTERNATE, LINK_LOCAL].contains(&source) {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "not ours"))
        }
    }

    // A delayed write that is still on the wire when it closes is failed, as
    // an adapter fails the frames its NIC queue still holds.
    fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        if state.stuck {
            return Poll::Pending;
        }
        while let Some(id) = state.delayed.pop_front() {
            state.completions.push_back((
                id,
                WriteOutcome::NotWritten(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "closed",
                )),
            ));
        }
        Poll::Ready(())
    }
}
