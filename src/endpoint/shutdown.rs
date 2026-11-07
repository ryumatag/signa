/*!
The future of a graceful shutdown.
*/

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::sync::{mpsc, watch};

use super::driver::Command;

/// One pending wakeup, regardless of the number of shutdown callers.
#[derive(Default, Debug)]
pub(super) struct Control(Mutex<State>);

#[derive(Default, Debug)]
struct State {
    requested: bool,
    queued: bool,
    deadline: Option<Instant>,
}

impl Control {
    pub(super) fn request(&self, timeout: Duration) -> bool {
        let at = tokio::time::Instant::now().into_std().checked_add(timeout);
        let mut state = self.0.lock().expect("shutdown state is not poisoned");
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

    pub(super) fn take(&self) -> Option<Instant> {
        let mut state = self.0.lock().expect("shutdown state is not poisoned");
        state.queued = false;
        state.deadline
    }
}

/// Resolves once the endpoint has stopped.
///
/// [`Endpoint::shutdown`] returns it. The future holds the endpoint's command
/// channel, so the endpoint keeps running while the future does, even when it
/// was the last handle. Dropping the future before it resolves gives up on
/// the wait. The endpoint then stops at once if no other handle is left, and
/// otherwise goes on to stop at the deadline.
///
/// [`Endpoint::shutdown`]: super::Endpoint::shutdown
pub struct Shutdown {
    /// Keeps the driver alive, see above.
    _commands: mpsc::UnboundedSender<Command>,
    /// Fails when the driver is gone, which is the signal. Nothing is ever
    /// sent on it.
    done: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
}

impl Shutdown {
    pub(super) fn new(
        commands: mpsc::UnboundedSender<Command>,
        mut done: watch::Receiver<()>,
    ) -> Shutdown {
        Shutdown {
            _commands: commands,
            done: Box::pin(async move {
                let _ = done.changed().await;
            }),
        }
    }
}

impl Future for Shutdown {
    type Output = ();

    fn poll(mut self: Pin<&mut Shutdown>, cx: &mut Context<'_>) -> Poll<()> {
        // Nothing is ever sent, so the only outcome is the closed channel.
        self.done.as_mut().poll(cx)
    }
}

impl fmt::Debug for Shutdown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shutdown").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_preserves_send_sync_and_unpin() {
        fn check<T: Send + Sync + Unpin>() {}
        check::<Shutdown>();
    }

    #[test]
    fn earliest_deadline_survives_coalescing_and_unrepresentable_timeouts() {
        let control = Control::default();
        assert!(control.request(Duration::MAX));
        assert!(!control.request(Duration::MAX));
        assert!(control.take().is_none());
        assert!(control.request(Duration::from_secs(30)));
        assert!(!control.request(Duration::ZERO));

        let earliest = control.take().unwrap();
        assert!(earliest <= tokio::time::Instant::now().into_std());
        assert!(!control.request(Duration::MAX));
        assert!(!control.request(Duration::from_secs(60)));
    }
}
