/*!
The future of a graceful shutdown.
*/

use std::{
    convert::Infallible,
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::sync::{mpsc, oneshot};

use super::driver::Command;

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
    done: oneshot::Receiver<Infallible>,
}

impl Shutdown {
    pub(super) fn new(
        commands: mpsc::UnboundedSender<Command>,
        done: oneshot::Receiver<Infallible>,
    ) -> Shutdown {
        Shutdown { _commands: commands, done }
    }
}

impl Future for Shutdown {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // Nothing is ever sent, so the only outcome is the closed channel.
        Pin::new(&mut self.done).poll(cx).map(drop)
    }
}

impl fmt::Debug for Shutdown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Shutdown")
    }
}
