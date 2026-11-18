/*!
Transaction settlement: when a transaction's machine and every write it made
have finished.

A transaction's settlement is apart from its observation. [`ServerEvents`]
coalesces failures and [`Responses`] can overflow, while what a [`Settled`]
counts is exact, kept from admission whether or not anyone watches, so that
neither telemetry loss nor a slow reader can lose it.

[`ServerEvents`]: super::ServerEvents
[`Responses`]: super::Responses
*/

use std::{
    fmt,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
};

use tokio::sync::{Notify, watch};

use super::server;
use crate::transport::datagram::WriteOutcome;

/// How a transaction settled: whether it drained or the endpoint stopped
/// first, and how its writes ended.
///
/// A transaction drains when its machine reaches Terminated and every write
/// it started has a local outcome. It counts each write the driver started
/// for it: its requests and their retransmissions and its non-2xx ACKs for a
/// client, every response for a server, the automatic 100, retransmissions
/// and signa's 500 included. A write that the endpoint's own limits refused
/// before the driver committed it is not counted. That is local saturation,
/// which the transaction's observation reports. One refused after, for want
/// of room for the connection it needed, counts as not written. The counts
/// are of local writes. None of them says that the peer received anything.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Settled {
    closed: bool,
    written: u32,
    not_written: u32,
    unknown: u32,
    abandoned: u32,
}

impl Settled {
    /// A settlement of which nothing is known but that the endpoint stopped.
    const CLOSED: Settled = Settled {
        closed: true,
        written: 0,
        not_written: 0,
        unknown: 0,
        abandoned: 0,
    };

    /// Whether the machine reached Terminated and every write ended before
    /// the endpoint stopped.
    ///
    /// It is `false` when the endpoint stopped first, at a shutdown deadline
    /// or when its last handle dropped, and dropped the machine or gave up on
    /// a write. A forced stop that came after the transaction drained leaves
    /// it `true`.
    pub fn is_drained(&self) -> bool {
        !self.closed
    }

    /// Writes that the transport wrote whole, which is not peer receipt.
    pub fn written(&self) -> u32 {
        self.written
    }

    /// Writes that did not go out: the transport refused or failed them, or
    /// a TCP connection they needed could not be opened. A TCP write can
    /// fail after a part of it went out.
    pub fn not_written(&self) -> u32 {
        self.not_written
    }

    /// Writes that a UDP backend took and could not account for. They may
    /// have gone out.
    pub fn outcome_unknown(&self) -> u32 {
        self.unknown
    }

    /// Writes that the endpoint gave up on as it stopped, before their
    /// outcome was known. Any of them makes [`Settled::is_drained`] `false`.
    pub fn abandoned(&self) -> u32 {
        self.abandoned
    }
}

/// Waits for a transaction to settle.
///
/// [`ServerTransaction::settlement`] and [`ClientTransaction::settlement`]
/// make one, as do the halves those split into. A settlement resolves once,
/// after the transaction's machine has terminated and every write it started
/// has ended, which can be after its response stream ended or its
/// [`ServerEvent::Terminated`]: a TCP write can still be queued, and a UDP
/// backend can report a write later. It also resolves when the endpoint
/// stops before then, with [`Settled::is_drained`] `false`.
///
/// It keeps neither the endpoint nor the transaction running, and dropping it
/// or its `wait` future cancels nothing. Any number of settlements can wait
/// for one transaction, and each sees the same [`Settled`].
///
/// [`ServerTransaction::settlement`]: super::ServerTransaction::settlement
/// [`ClientTransaction::settlement`]: super::ClientTransaction::settlement
/// [`ServerEvent::Terminated`]: super::ServerEvent::Terminated
#[derive(Clone)]
pub struct Settlement(Source);

#[derive(Clone)]
enum Source {
    /// A server transaction's observation channel, which carries the
    /// [`Settled`] once there is one. As a receiver it also keeps the entry
    /// from dropping the transaction's state at the final response, see
    /// `Driver::accept_response`.
    Server(watch::Receiver<server::Observation>),
    Client(Arc<Settle>),
}

impl Settlement {
    pub(super) fn server(
        receiver: watch::Receiver<server::Observation>,
    ) -> Settlement {
        Settlement(Source::Server(receiver))
    }

    pub(super) fn client(settle: Arc<Settle>) -> Settlement {
        Settlement(Source::Client(settle))
    }

    /// Returns how the transaction settled, or `None` while it has not.
    pub fn get(&self) -> Option<Settled> {
        match &self.0 {
            Source::Server(receiver) => receiver.borrow().settled,
            Source::Client(settle) => settle.tally.settled(),
        }
    }

    /// Waits until the transaction settles.
    ///
    /// It is cancellation-safe, and dropping it has no effect on the
    /// transaction.
    ///
    /// # Example
    ///
    /// A UAC keeps its INVITE's call state until the transaction has
    /// settled, so that a late write failure still finds it.
    ///
    /// ```
    /// use signa_core::endpoint::ClientTransaction;
    ///
    /// async fn settle(invite: ClientTransaction) {
    ///     let settlement = invite.settlement();
    ///     let (_control, mut responses) = invite.into_parts();
    ///     while let Some(_response) = responses.next().await {
    ///         // Acknowledge each 2xx, as the `Responses` example does.
    ///     }
    ///
    ///     // The stream has ended, at the final or at Timer M. The machine
    ///     // can still be absorbing retransmissions, and a write can still
    ///     // be in flight.
    ///     let settled = settlement.wait().await;
    ///     if !settled.is_drained() {
    ///         eprintln!("the endpoint stopped before the INVITE ended");
    ///     } else if settled.not_written() > 0 {
    ///         eprintln!("{} writes failed", settled.not_written());
    ///     }
    /// }
    /// ```
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn wait(&self) -> impl Future<Output = Settled> + Send + '_ {
        async move {
            match &self.0 {
                Source::Server(receiver) => {
                    let mut receiver = receiver.clone();
                    match receiver
                        .wait_for(|state| state.settled.is_some())
                        .await
                    {
                        Ok(state) => state.settled.expect("waited for it"),
                        // The writes in progress and the driver's entry hold
                        // the sender until the settlement is published, so
                        // this is a transaction that went without one.
                        Err(_) => Settled::CLOSED,
                    }
                }
                Source::Client(settle) => {
                    loop {
                        let notified = settle.notify.notified();
                        let mut notified = std::pin::pin!(notified);
                        // Enabled before the check, so a settlement after it
                        // still wakes this waiter.
                        notified.as_mut().enable();
                        if let Some(settled) = settle.tally.settled() {
                            return settled;
                        }
                        notified.await;
                    }
                }
            }
        }
    }
}

impl fmt::Debug for Settlement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Settlement").field(&self.get()).finish()
    }
}

/// How one write of a transaction ended, as its tally counts it.
#[derive(Clone, Copy)]
pub(super) enum Ending {
    Written,
    NotWritten,
    Unknown,
    /// The endpoint stopped before the outcome was known.
    Abandoned,
}

impl From<&WriteOutcome> for Ending {
    fn from(outcome: &WriteOutcome) -> Ending {
        match outcome {
            WriteOutcome::Written => Ending::Written,
            WriteOutcome::NotWritten(_) => Ending::NotWritten,
            WriteOutcome::Unknown(_) => Ending::Unknown,
        }
    }
}

/// The writes of a transaction in progress, in the low half of
/// [`Tally::state`]. The driver's write limits keep them far below 2^32.
const WRITES: u64 = u32::MAX as u64;
/// The machine has not ended.
const LIVE: u64 = 1 << 32;
/// The machine was dropped by an endpoint that stopped first.
const CLOSED: u64 = 1 << 33;

/// The exact count behind a [`Settled`], made with the transaction.
///
/// `state` holds the writes in progress and whether the machine lives, and
/// the transaction has settled once both are gone. Whoever clears the last
/// of them settled it, which therefore happens exactly once, with no lock.
/// Every count is stored before that change, which releases it, and read
/// after a load that sees it and acquires it, so a [`Settled`] is complete
/// when it is read.
///
/// A write starts only while the machine lives, since the driver writes for
/// transactions in its tables, so the state does not leave the settled one.
/// One word keeps a client transaction's [`Settle`] within 64 bytes.
pub(super) struct Tally {
    state: AtomicU64,
    written: AtomicU32,
    not_written: AtomicU32,
    unknown: AtomicU32,
    abandoned: AtomicU32,
}

impl Tally {
    pub(super) fn new() -> Tally {
        Tally {
            state: AtomicU64::new(LIVE),
            written: AtomicU32::new(0),
            not_written: AtomicU32::new(0),
            unknown: AtomicU32::new(0),
            abandoned: AtomicU32::new(0),
        }
    }

    /// Counts a write that has started and not ended.
    pub(super) fn start(&self) {
        let before = self.state.fetch_add(1, Ordering::Relaxed);
        debug_assert!(before & WRITES != WRITES, "writes overflow");
    }

    /// Ends a write that [`Tally::start`] counted. Returns `true` if this
    /// settled the transaction.
    pub(super) fn end(&self, ending: Ending) -> bool {
        self.count(ending);
        // The last write of a machine that has ended, however it ended.
        self.state.fetch_sub(1, Ordering::AcqRel) & (LIVE | WRITES) == 1
    }

    /// Counts a write whose outcome was known as it started, so it was never
    /// in progress.
    pub(super) fn record(&self, ending: Ending) {
        self.count(ending);
    }

    fn count(&self, ending: Ending) {
        let counter = match ending {
            Ending::Written => &self.written,
            Ending::NotWritten => &self.not_written,
            Ending::Unknown => &self.unknown,
            Ending::Abandoned => &self.abandoned,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Ends the machine, as Terminated or, with `closed`, as dropped by an
    /// endpoint that stopped first. Only the first call counts. Returns
    /// `true` if this settled the transaction.
    pub(super) fn end_machine(&self, closed: bool) -> bool {
        let ended = if closed { CLOSED } else { 0 };
        let mut state = self.state.load(Ordering::Relaxed);
        while state & LIVE != 0 {
            match self.state.compare_exchange_weak(
                state,
                (state - LIVE) | ended,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                // Settled when no write was in progress as it ended.
                Ok(_) => return state & WRITES == 0,
                Err(actual) => state = actual,
            }
        }
        false
    }

    /// Whether the machine reached Terminated, rather than living on or
    /// being dropped.
    pub(super) fn is_terminated(&self) -> bool {
        self.state.load(Ordering::Relaxed) & (LIVE | CLOSED) == 0
    }

    pub(super) fn settled(&self) -> Option<Settled> {
        let state = self.state.load(Ordering::Acquire);
        if state & (LIVE | WRITES) != 0 {
            return None;
        }

        let abandoned = self.abandoned.load(Ordering::Relaxed);
        Some(Settled {
            closed: state & CLOSED != 0 || abandoned != 0,
            written: self.written.load(Ordering::Relaxed),
            not_written: self.not_written.load(Ordering::Relaxed),
            unknown: self.unknown.load(Ordering::Relaxed),
            abandoned,
        })
    }
}

/// A client transaction's [`Tally`] and the waiters of its settlements.
///
/// It is an allocation of its own, which the transaction's handles, its
/// table entry and its writes in progress share, 64 bytes and the `Arc`'s
/// counts. A server transaction keeps its tally in the state it has anyway.
pub(super) struct Settle {
    pub(super) tally: Tally,
    notify: Notify,
}

impl fmt::Debug for Settle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Settle").field(&self.tally.settled()).finish()
    }
}

impl Settle {
    pub(super) fn new() -> Settle {
        Settle { tally: Tally::new(), notify: Notify::new() }
    }

    /// See [`Tally::end`]. Wakes the waiters if this settled it.
    pub(super) fn end(&self, ending: Ending) {
        if self.tally.end(ending) {
            self.notify.notify_waiters();
        }
    }

    /// See [`Tally::end_machine`]. Wakes the waiters if this settled it.
    pub(super) fn end_machine(&self, closed: bool) {
        if self.tally.end_machine(closed) {
            self.notify.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use quickcheck::QuickCheck;

    use super::*;

    // Whatever order writes start and end in around the end of the machine,
    // exactly the last of them settles the transaction, and the settlement
    // counts each write once.
    #[test]
    fn any_order_settles_once_with_every_write_counted() {
        fn property(events: Vec<u8>, machine: u8, closed: bool) -> bool {
            let tally = Tally::new();
            let mut open = 0usize;
            let mut ended = false;
            let mut settled = 0;
            let mut counts = [0u32; 4];
            let machine = usize::from(machine) % (events.len() + 1);
            for (index, event) in events.iter().enumerate() {
                if index == machine {
                    settled += usize::from(tally.end_machine(closed));
                    ended = true;
                }
                // A write starts only while the machine lives.
                if event % 2 == 0 && !ended {
                    tally.start();
                    open += 1;
                } else if open > 0 {
                    let kind = usize::from(event / 2 % 4);
                    let ending = [
                        Ending::Written,
                        Ending::NotWritten,
                        Ending::Unknown,
                        Ending::Abandoned,
                    ][kind];
                    counts[kind] += 1;
                    open -= 1;
                    let done = tally.end(ending);
                    if done != (ended && open == 0) {
                        return false;
                    }
                    settled += usize::from(done);
                }
                if tally.settled().is_some() != (ended && open == 0) {
                    return false;
                }
            }
            if !ended {
                settled += usize::from(tally.end_machine(closed));
            }
            while open > 0 {
                counts[0] += 1;
                open -= 1;
                settled += usize::from(tally.end(Ending::Written));
            }

            let result = tally.settled().unwrap();
            settled == 1
                && [
                    result.written(),
                    result.not_written(),
                    result.outcome_unknown(),
                    result.abandoned(),
                ] == counts
                && result.is_drained() == (!closed && counts[3] == 0)
        }

        QuickCheck::new()
            .tests(1000)
            .quickcheck(property as fn(Vec<u8>, u8, bool) -> bool);
    }

    #[test]
    fn settles_once_after_the_machine_and_its_writes() {
        let tally = Tally::new();
        tally.start();
        tally.start();
        tally.record(Ending::NotWritten);

        assert!(!tally.end(Ending::Written));
        assert!(!tally.end_machine(false));
        assert_eq!(tally.settled(), None);
        assert!(tally.end(Ending::Unknown));

        let settled = tally.settled().unwrap();
        assert!(settled.is_drained());
        assert_eq!(
            (
                settled.written(),
                settled.not_written(),
                settled.outcome_unknown(),
                settled.abandoned(),
            ),
            (1, 1, 1, 0),
        );
    }

    #[test]
    fn only_the_first_machine_end_counts() {
        let tally = Tally::new();
        assert!(tally.end_machine(false));
        assert!(!tally.end_machine(true));
        assert!(tally.is_terminated());
        assert!(tally.settled().unwrap().is_drained());
    }

    #[test]
    fn a_closed_machine_or_an_abandoned_write_is_not_a_drain() {
        let closed = Tally::new();
        assert!(closed.end_machine(true));
        assert!(!closed.is_terminated());
        assert!(!closed.settled().unwrap().is_drained());

        let abandoned = Tally::new();
        abandoned.start();
        assert!(!abandoned.end_machine(false));
        assert!(abandoned.end(Ending::Abandoned));
        let settled = abandoned.settled().unwrap();
        assert!(!settled.is_drained());
        assert_eq!(settled.abandoned(), 1);
    }

    #[tokio::test]
    async fn every_client_waiter_wakes() {
        let settle = Arc::new(Settle::new());
        let first = Settlement::client(settle.clone());
        let second = first.clone();
        let waiting = tokio::spawn(async move { second.wait().await });
        tokio::task::yield_now().await;

        settle.end_machine(false);

        assert!(first.wait().await.is_drained());
        assert!(waiting.await.unwrap().is_drained());
    }
}
