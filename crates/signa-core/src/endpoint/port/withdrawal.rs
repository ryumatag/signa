/*!
The point after which a shared port's backend takes no more of an endpoint's
writes.

An endpoint stopping at its deadline does not wait for the port's task to
handle its unregistration. Its writes can still wait in the task's command
queue or in the backlog of writes the backend could not take yet, and the
task would offer them after the endpoint had reported itself stopped. A flag
that the task read before offering would not be enough either. The endpoint
could set it between the read and the offer.

So the flag sits behind a lock that both sides take:

* [`Withdrawal::withdraw`] sets the flag under the lock.
* [`Withdrawal::offer`] reads the flag under the lock and, only while it is
  clear, offers the write, holding the lock until `poll_submit` returns.

The two exclude each other, so one comes first. An offer that came first has
returned before the withdrawal finishes, and the write it offered counts as
taken before the endpoint stopped. A withdrawal that came first makes every
later offer refuse. Once `withdraw` returns, the backend accepts none of the
endpoint's writes. A write it accepted before may still go out, since nothing
here can take it back from the backend.

The lock is held across a backend's `poll_submit`, which must return without
waiting, as `DatagramIo::poll_submit` asks. Nothing else runs under it. The
caller settles the outcome, and returns the write's share of the port's
write limits, after the lock is released. An endpoint stopping waits at most
for the one offer in progress, and the admission lock is never taken under
this one.
*/

use std::sync::{
    Mutex, PoisonError,
    atomic::{AtomicBool, Ordering},
};

/// Whether an endpoint on a shared port has withdrawn, with the lock that
/// makes withdrawing a barrier for the backend's offers.
#[derive(Debug, Default)]
pub(crate) struct Withdrawal {
    gate: Mutex<()>,
    withdrawn: AtomicBool,
}

impl Withdrawal {
    /// Withdraws the endpoint. Once this returns, [`Withdrawal::offer`]
    /// refuses every write, and no offer is in progress.
    pub(crate) fn withdraw(&self) {
        // Only the flag changes under the lock, so a poisoned one is still
        // sound to take.
        let _gate = self.gate.lock().unwrap_or_else(PoisonError::into_inner);
        self.withdrawn.store(true, Ordering::Release);
    }

    /// Returns `true` once the endpoint has withdrawn.
    ///
    /// It is a hint for refusing early. Only [`Withdrawal::offer`] decides
    /// whether a write reaches the backend.
    pub(crate) fn is_withdrawn(&self) -> bool {
        self.withdrawn.load(Ordering::Acquire)
    }

    /// Runs `submit`, which offers a write to the backend, unless the
    /// endpoint has withdrawn. Returns `None` if it has, without running it.
    pub(crate) fn offer<T>(&self, submit: impl FnOnce() -> T) -> Option<T> {
        let _gate = self.gate.lock().unwrap_or_else(PoisonError::into_inner);
        // The lock orders this read after any withdrawal that finished.
        if self.withdrawn.load(Ordering::Relaxed) {
            return None;
        }
        Some(submit())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, mpsc},
        thread,
        time::Duration,
    };

    use super::*;

    #[test]
    fn a_withdrawal_refuses_every_later_offer() {
        let withdrawal = Withdrawal::default();
        assert_eq!(withdrawal.offer(|| 1), Some(1));

        withdrawal.withdraw();

        assert!(withdrawal.is_withdrawn());
        let mut ran = false;
        assert_eq!(withdrawal.offer(|| ran = true), None);
        assert!(!ran);
    }

    // An offer in progress finishes before a withdrawal that starts during
    // it. The offer is held inside `submit` until the test has seen the
    // withdrawal wait, so the order is fixed by the test, not by timing.
    #[test]
    fn a_withdrawal_waits_for_the_offer_in_progress() {
        let withdrawal = Arc::new(Withdrawal::default());
        let (entered, offering) = mpsc::channel();
        let (release, held) = mpsc::channel::<()>();
        let offer = thread::spawn({
            let withdrawal = withdrawal.clone();
            move || {
                withdrawal.offer(|| {
                    entered.send(()).unwrap();
                    let _ = held.recv();
                })
            }
        });
        offering.recv().unwrap();

        let (withdrawn, done) = mpsc::channel();
        let withdraw = thread::spawn({
            let withdrawal = withdrawal.clone();
            move || {
                withdrawal.withdraw();
                withdrawn.send(()).unwrap();
            }
        });
        let waited = done.recv_timeout(Duration::from_millis(50)).is_err();
        // Released before any assertion, so that a failure cannot leave the
        // offering thread blocked.
        release.send(()).unwrap();

        assert!(waited, "the withdrawal finished during an offer");
        assert_eq!(offer.join().unwrap(), Some(()));
        done.recv().unwrap();
        withdraw.join().unwrap();
        assert_eq!(withdrawal.offer(|| ()), None);
    }
}
