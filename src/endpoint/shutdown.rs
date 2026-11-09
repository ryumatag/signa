/*!
Graceful shutdown: the coalesced request, TU work guards, and the future that
reports how the endpoint stopped.
*/

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::sync::{mpsc, watch};

use super::{driver::Command, Error};

/// How an endpoint stopped, as [`Shutdown`] reports it.
///
/// This is signa's lifecycle contract, not something RFC 3261 defines. The
/// RFCs only say which transaction state outlives a final response, and the
/// drain waits for it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ShutdownOutcome {
    /// Everything the endpoint had taken on finished before the deadline:
    /// every transaction reached Terminated, every [`WorkGuard`] dropped, and
    /// every accepted write and connect completed. No observer saw a closed
    /// error for it.
    ///
    /// The listener and connection tasks have ended too. One still closing at
    /// the deadline is stopped then, which leaves this a drain as long as it
    /// had no output left to drop.
    Drained,
    /// The deadline came first. The endpoint dropped what was left, observers
    /// of it saw [`Error::is_closed`] or [`ServerEvent::EndpointClosed`], and
    /// unwritten TCP output was discarded. The transport tasks still ended
    /// before this was reported.
    ///
    /// Dropping [`Incoming`] asks for a deadline of now, so it ends here
    /// unless nothing was left at that moment. An endpoint task that stops
    /// without finishing, such as when its runtime shuts down, also reports
    /// this, since its work was not shown to have drained.
    ///
    /// [`Error::is_closed`]: super::Error::is_closed
    /// [`ServerEvent::EndpointClosed`]: super::ServerEvent::EndpointClosed
    /// [`Incoming`]: super::Incoming
    DeadlineExpired,
}

impl ShutdownOutcome {
    /// Whether the endpoint drained before its deadline.
    pub fn is_drained(self) -> bool {
        self == ShutdownOutcome::Drained
    }
}

/// Holds a graceful shutdown open for work the transaction user does outside
/// any transaction.
///
/// [`Endpoint::work_guard`] returns one. While any guard is alive,
/// [`Endpoint::shutdown`] keeps draining instead of reporting
/// [`ShutdownOutcome::Drained`]. Dropping the guard says that the work is done.
/// The drop is synchronous and cannot be lost, and the last one wakes the
/// endpoint to check whether it has drained. A guard costs no task and no
/// queued command, however many there are.
///
/// # What needs one
///
/// Typical work is a UAS waiting for the ACK of its 2xx and retransmitting the
/// 2xx through the request's [`ReplyRoute`] until then
/// ([RFC 3261 section 13.3.1.4]). The INVITE's own transaction stays in
/// Accepted for Timer L, which the drain waits for anyway, but the TU's ACK
/// wait and retransmissions are the TU's and only a guard holds the drain for
/// them. Keeping an [`Endpoint`], a [`ReplyRoute`] or any other handle does
/// not.
///
/// # Lifetime
///
/// A guard also keeps the endpoint running, as an [`Endpoint`] does. The
/// deadline of a shutdown does not wait for guards. After it, dropping a
/// guard has no effect. A guard that is never dropped, for example one passed
/// to [`std::mem::forget`], holds every graceful shutdown until its deadline.
///
/// # Example
///
/// A task the TU owns takes its guard before it starts, so a shutdown that
/// begins meanwhile waits for it.
///
/// ```
/// use std::time::Duration;
///
/// use signa::endpoint::{Endpoint, ShutdownOutcome};
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let (endpoint, _incoming) =
///     Endpoint::builder().udp("127.0.0.1:0".parse()?).bind()?;
///
/// let guard = endpoint.work_guard()?;
/// let task = tokio::spawn(async move {
///     let _guard = guard;
///     // Retransmit a 2xx until its ACK arrives, say.
///     tokio::time::sleep(Duration::from_millis(100)).await;
/// });
///
/// // Resolves after the task has dropped its guard, or after 40 seconds.
/// let outcome = endpoint.shutdown(Duration::from_secs(40)).await;
/// assert_eq!(outcome, ShutdownOutcome::Drained);
/// # drop(task);
/// # Ok(())
/// # }
/// ```
///
/// [`Endpoint::work_guard`]: super::Endpoint::work_guard
/// [`Endpoint::shutdown`]: super::Endpoint::shutdown
/// [`Endpoint`]: super::Endpoint
/// [`ReplyRoute`]: super::ReplyRoute
/// [RFC 3261 section 13.3.1.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4
pub struct WorkGuard {
    control: Arc<Control>,
    wake: mpsc::Sender<()>,
    _endpoint: mpsc::UnboundedSender<Command>,
}

impl WorkGuard {
    pub(super) fn new(
        control: Arc<Control>,
        wake: mpsc::Sender<()>,
        endpoint: mpsc::UnboundedSender<Command>,
    ) -> Result<WorkGuard, Error> {
        control.acquire_guard()?;

        Ok(WorkGuard { control, wake, _endpoint: endpoint })
    }
}

impl Drop for WorkGuard {
    fn drop(&mut self) {
        // A full wakeup queue already holds a wakeup, after which the driver
        // checks again whether it has drained.
        if self.control.release_guard() {
            let _ = self.wake.try_send(());
        }
    }
}

impl fmt::Debug for WorkGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkGuard").finish_non_exhaustive()
    }
}

/// Resolves once the endpoint has stopped, with how it stopped.
///
/// [`Endpoint::shutdown`] returns it. It resolves after the endpoint has
/// dropped its transactions and its listener and TCP connection tasks have
/// ended, so nothing the endpoint owns sends anything after that. Every
/// waiter gets the same [`ShutdownOutcome`].
///
/// The future holds the endpoint's command channel, so the endpoint keeps
/// running while the future does, even when it was the last handle. Dropping
/// the future before it resolves gives up on the wait, not on the shutdown.
/// The endpoint then stops at once if no other handle is left, and otherwise
/// goes on draining until the deadline.
///
/// [`Endpoint::shutdown`]: super::Endpoint::shutdown
pub struct Shutdown {
    /// Keeps the driver alive, see above.
    _commands: mpsc::UnboundedSender<Command>,
    done: Pin<Box<dyn Future<Output = ShutdownOutcome> + Send + Sync>>,
}

impl Shutdown {
    pub(super) fn new(
        commands: mpsc::UnboundedSender<Command>,
        mut done: watch::Receiver<Option<ShutdownOutcome>>,
    ) -> Shutdown {
        Shutdown {
            _commands: commands,
            done: Box::pin(async move {
                loop {
                    if let Some(outcome) = *done.borrow_and_update() {
                        return outcome;
                    }
                    if done.changed().await.is_err() {
                        return done
                            .borrow()
                            .unwrap_or(ShutdownOutcome::DeadlineExpired);
                    }
                }
            }),
        }
    }
}

impl Future for Shutdown {
    type Output = ShutdownOutcome;

    fn poll(
        mut self: Pin<&mut Shutdown>,
        cx: &mut Context<'_>,
    ) -> Poll<ShutdownOutcome> {
        self.done.as_mut().poll(cx)
    }
}

impl fmt::Debug for Shutdown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shutdown").finish()
    }
}

/// The guard count's top bit. Once set, no guard can be taken.
const CLOSED: usize = 1 << (usize::BITS - 1);

/// One pending wakeup, regardless of the number of shutdown callers, and the
/// count of live [`WorkGuard`]s.
#[derive(Default, Debug)]
pub(super) struct Control {
    state: Mutex<State>,
    /// Live guards below [`CLOSED`]. The driver sets [`CLOSED`] when it stops,
    /// and only while the count is zero unless the deadline has passed. A
    /// compare-and-swap decides the race between that and a new guard, so a
    /// guard is either counted before the endpoint decides it has drained or
    /// refused.
    guards: AtomicUsize,
}

#[derive(Default, Debug)]
struct State {
    requested: bool,
    queued: bool,
    deadline: Option<Instant>,
}

impl Control {
    /// Records a shutdown request. Returns whether the driver needs a wakeup
    /// for it, which it does unless one is already queued or an earlier
    /// deadline is in force.
    ///
    /// A timeout too large to add to now means no deadline.
    pub(super) fn request(&self, timeout: Duration) -> bool {
        let at = tokio::time::Instant::now().into_std().checked_add(timeout);
        let mut state =
            self.state.lock().expect("shutdown state is not poisoned");
        let earlier =
            at.is_some_and(|at| state.deadline.map_or(true, |old| at < old));
        if state.requested && !earlier {
            return false;
        }

        state.requested = true;
        if earlier {
            state.deadline = at;
        }
        let enqueue = !state.queued;
        state.queued = true;

        enqueue
    }

    /// Takes a queued request. `None` means that the wakeup was for something
    /// else, such as the last guard's drop, or that the request was already
    /// taken. `Some(None)` is a request without a deadline.
    pub(super) fn take(&self) -> Option<Option<Instant>> {
        let mut state =
            self.state.lock().expect("shutdown state is not poisoned");
        if !state.queued {
            return None;
        }
        state.queued = false;

        Some(state.deadline)
    }

    fn acquire_guard(&self) -> Result<(), Error> {
        let mut current = self.guards.load(Ordering::Relaxed);
        loop {
            if current & CLOSED != 0 {
                return Err(Error::closed());
            }
            // A count that would reach the closed bit would read as a closed
            // endpoint. Only leaked guards get there.
            if current + 1 == CLOSED {
                return Err(Error::busy());
            }
            match self.guards.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    /// Returns whether this was the last guard of an endpoint still running.
    fn release_guard(&self) -> bool {
        self.guards.fetch_sub(1, Ordering::AcqRel) == 1
    }

    /// Whether no guard is alive, closed or not.
    pub(super) fn guards_idle(&self) -> bool {
        self.guards.load(Ordering::Acquire) & !CLOSED == 0
    }

    /// Refuses new guards if none is live. Returns whether they are refused
    /// now, which they also are when an earlier call refused them.
    pub(super) fn close_guards_if_idle(&self) -> bool {
        match self.guards.compare_exchange(
            0,
            CLOSED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => true,
            Err(current) => current == CLOSED,
        }
    }

    /// Refuses new guards whatever is live. Live guards may still drop.
    pub(super) fn close_guards(&self) {
        self.guards.fetch_or(CLOSED, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_and_guards_preserve_send_sync_and_unpin() {
        fn check<T: Send + Sync + Unpin>() {}
        check::<Shutdown>();
        check::<WorkGuard>();
    }

    #[test]
    fn earliest_deadline_survives_coalescing_and_unrepresentable_timeouts() {
        let control = Control::default();
        assert!(control.request(Duration::MAX));
        assert!(!control.request(Duration::MAX));
        assert_eq!(control.take(), Some(None));
        assert_eq!(control.take(), None);
        assert!(control.request(Duration::from_secs(30)));
        assert!(!control.request(Duration::ZERO));

        let earliest = control.take().unwrap().unwrap();
        assert!(earliest <= tokio::time::Instant::now().into_std());
        assert!(!control.request(Duration::MAX));
        assert!(!control.request(Duration::from_secs(60)));
        assert_eq!(control.take(), None);
    }

    #[test]
    fn guards_count_independently_and_close_without_a_race() {
        let control = Control::default();
        control.acquire_guard().unwrap();
        control.acquire_guard().unwrap();
        assert!(!control.close_guards_if_idle());

        assert!(!control.release_guard());
        assert!(!control.guards_idle());
        assert!(control.release_guard());
        assert!(control.guards_idle());

        assert!(control.close_guards_if_idle());
        assert!(control.close_guards_if_idle());
        assert!(control.acquire_guard().unwrap_err().is_closed());
    }

    #[test]
    fn a_forced_close_lets_live_guards_drop_quietly() {
        let control = Control::default();
        control.acquire_guard().unwrap();
        control.close_guards();

        assert!(control.acquire_guard().unwrap_err().is_closed());
        assert!(!control.release_guard());
        assert!(control.guards_idle());
    }

    #[test]
    fn the_guard_count_cannot_reach_the_closed_bit() {
        let control = Control::default();
        control.guards.store(CLOSED - 1, Ordering::Relaxed);

        assert!(control.acquire_guard().unwrap_err().is_busy());
        assert!(!control.release_guard());
        control.acquire_guard().unwrap();
    }
}
