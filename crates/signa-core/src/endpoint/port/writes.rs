/*!
The port-wide write limits, which every registered endpoint and the raw sends
share.

One lock covers the counts, the endpoints waiting for room and whether the
port is closing. An admission checks the count and the bytes and takes both
together, so a refused one leaves nothing to undo and nothing to announce. An
endpoint that finds the limits full leaves its waker under the same lock that
a release or a close takes to collect the wakers. Either the release comes
first and the admission sees its room, or the waker is in place and the
release takes it.

Wakers run once the lock is released. A waker is the executor's code, and
nothing says it cannot come back into the port.

Every waiter is woken at each release and they race for the room. The limits
bound the contention, but no endpoint is promised a share of them or a bound
on its wait. An endpoint with a backend of its own never takes this lock.
*/

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt, mem,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::Waker,
};

use crate::transport::{Limits, budget::request_limits};

/// The port's write limits and who waits for room in them.
pub(super) struct WriteAdmission(Arc<Shared>);

struct Shared {
    limits: Limits,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    count: usize,
    bytes: usize,
    /// Set once the port closes. Nothing is admitted and nobody waits after.
    closed: bool,
    /// One waker per registration, the latest, so that polling more often
    /// does not keep more.
    waiters: HashMap<u64, Waker>,
}

/// What became of a request for room.
pub(super) enum Admission {
    Admitted(WritePermit),
    /// No room now. An endpoint's waker is left to be woken when some frees
    /// up or the port closes.
    Full,
    /// The port is closing.
    Closed,
}

impl Shared {
    // Nothing panics while the lock is held, short of a broken count. A
    // poisoned lock is still read, so that a permit dropped while a thread
    // unwinds cannot panic again.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl WriteAdmission {
    pub(super) fn new(limits: Limits) -> WriteAdmission {
        WriteAdmission(Arc::new(Shared { limits, state: Mutex::default() }))
    }

    /// Takes room for a write of `len` bytes by the endpoint registered as
    /// `registration`, or leaves `waker` to be woken when room frees up.
    pub(super) fn admit(
        &self,
        registration: u64,
        len: usize,
        waker: &Waker,
    ) -> Admission {
        let replaced = {
            let mut state = self.0.state();
            if state.closed {
                return Admission::Closed;
            }
            if let Some(permit) = self.take(&mut state, len, self.0.limits) {
                return Admission::Admitted(permit);
            }
            match state.waiters.entry(registration) {
                Entry::Occupied(mut waiter) => {
                    if waiter.get().will_wake(waker) {
                        None
                    } else {
                        Some(waiter.insert(waker.clone()))
                    }
                }
                Entry::Vacant(waiter) => {
                    waiter.insert(waker.clone());
                    None
                }
            }
        };
        // A waker's drop is the executor's code too.
        drop(replaced);
        Admission::Full
    }

    /// Takes room for a raw send of `len` bytes within the three quarters of
    /// the limits that raw sends may use. A raw send never waits.
    pub(super) fn admit_raw(&self, len: usize) -> Admission {
        let mut state = self.0.state();
        if state.closed {
            return Admission::Closed;
        }
        match self.take(&mut state, len, request_limits(self.0.limits)) {
            Some(permit) => Admission::Admitted(permit),
            None => Admission::Full,
        }
    }

    fn take(
        &self,
        state: &mut State,
        len: usize,
        limits: Limits,
    ) -> Option<WritePermit> {
        if state.count >= limits.count {
            return None;
        }
        let bytes = state
            .bytes
            .checked_add(len)
            .filter(|&bytes| bytes <= limits.bytes)?;
        state.count += 1;
        state.bytes = bytes;
        Some(WritePermit { limits: self.0.clone(), bytes: len })
    }

    /// Refuses every later admission and wakes the endpoints waiting, which
    /// then find the port closing.
    pub(super) fn close(&self) {
        let waiters = {
            let mut state = self.0.state();
            state.closed = true;
            mem::take(&mut state.waiters)
        };
        wake(waiters);
    }

    /// Returns `true` when no write holds room. A write is admitted before
    /// its command is queued, so then none is on its way to the port's task
    /// either.
    pub(super) fn is_idle(&self) -> bool {
        self.0.state().count == 0
    }

    /// Forgets the waker of a registration that has ended.
    pub(super) fn forget(&self, registration: u64) {
        let waker = self.0.state().waiters.remove(&registration);
        drop(waker);
    }
}

/// A write's share of the port's limits, which it holds until its outcome is
/// known.
pub(crate) struct WritePermit {
    limits: Arc<Shared>,
    bytes: usize,
}

impl Drop for WritePermit {
    /// Returns the room and wakes every endpoint waiting for it.
    fn drop(&mut self) {
        let waiters = {
            let mut state = self.limits.state();
            state.count -= 1;
            state.bytes -= self.bytes;
            mem::take(&mut state.waiters)
        };
        wake(waiters);
    }
}

impl fmt::Debug for WritePermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WritePermit").field("bytes", &self.bytes).finish()
    }
}

fn wake(waiters: HashMap<u64, Waker>) {
    for waker in waiters.into_values() {
        waker.wake();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        task::Wake,
    };

    use super::*;

    /// Counts how often it was woken.
    #[derive(Default)]
    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Count>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn counter() -> (Arc<Count>, Waker) {
        let count = Arc::new(Count::default());
        (count.clone(), Waker::from(count))
    }

    fn woken(count: &Count) -> usize {
        count.0.load(Ordering::Relaxed)
    }

    fn admitted(admission: Admission) -> WritePermit {
        match admission {
            Admission::Admitted(permit) => permit,
            Admission::Full => panic!("expected room, found the limits full"),
            Admission::Closed => {
                panic!("expected room, found the port closed")
            }
        }
    }

    fn usage(admission: &WriteAdmission) -> (usize, usize) {
        let state = admission.0.state();
        (state.count, state.bytes)
    }

    // A raw send too large for its three quarters is refused without taking
    // the one message slot even for a moment, and an endpoint's write gets
    // it. Taking the slot first and the bytes after, then handing the slot
    // back, used to leave an endpoint that saw it taken waiting with nothing
    // to wake it.
    #[test]
    fn a_refused_raw_send_takes_nothing() {
        let admission = WriteAdmission::new(Limits { count: 1, bytes: 1472 });
        let (count, waker) = counter();

        assert!(matches!(admission.admit_raw(1200), Admission::Full));
        assert_eq!(usage(&admission), (0, 0));
        let permit = admitted(admission.admit(1, 100, &waker));
        assert_eq!(usage(&admission), (1, 100));
        assert_eq!(woken(&count), 0);
        drop(permit);
        assert_eq!(usage(&admission), (0, 0));
    }

    // An endpoint waiting while a raw send is refused is woken by the
    // release that makes room, with no other traffic.
    #[test]
    fn a_waiter_is_woken_by_the_release_whatever_was_refused_meanwhile() {
        let admission = WriteAdmission::new(Limits { count: 1, bytes: 1472 });
        let (count, waker) = counter();
        let held = admitted(admission.admit(1, 10, &waker));

        assert!(matches!(admission.admit(2, 10, &waker), Admission::Full));
        assert!(matches!(admission.admit_raw(1200), Admission::Full));
        assert!(matches!(admission.admit_raw(10), Admission::Full));
        assert_eq!(woken(&count), 0);

        drop(held);
        assert_eq!(woken(&count), 1);
        drop(admitted(admission.admit(2, 10, &waker)));
    }

    // Polling again keeps one waker per registration, the latest.
    #[test]
    fn a_registration_keeps_one_waker() {
        let admission = WriteAdmission::new(Limits { count: 1, bytes: 10 });
        let (_, holder) = counter();
        let held = admitted(admission.admit(1, 10, &holder));
        let (old, old_waker) = counter();
        let (new, new_waker) = counter();

        for _ in 0..3 {
            assert!(matches!(
                admission.admit(2, 1, &old_waker),
                Admission::Full
            ));
        }
        assert!(matches!(admission.admit(2, 1, &new_waker), Admission::Full));
        assert_eq!(admission.0.state().waiters.len(), 1);

        drop(held);
        assert_eq!((woken(&old), woken(&new)), (0, 1));
    }

    // A close wakes the waiters and refuses everything after, so that none
    // can wait after the last wake. Writes admitted before still return
    // their room.
    #[test]
    fn a_close_wakes_the_waiters_and_leaves_none_after() {
        let admission = WriteAdmission::new(Limits { count: 1, bytes: 10 });
        let (count, waker) = counter();
        let held = admitted(admission.admit(1, 10, &waker));
        assert!(matches!(admission.admit(2, 1, &waker), Admission::Full));

        admission.close();
        assert_eq!(woken(&count), 1);
        assert!(matches!(admission.admit(2, 1, &waker), Admission::Closed));
        assert!(matches!(admission.admit_raw(1), Admission::Closed));
        assert!(admission.0.state().waiters.is_empty());

        drop(held);
        assert_eq!(usage(&admission), (0, 0));
    }

    #[test]
    fn a_forgotten_registration_is_not_woken() {
        let admission = WriteAdmission::new(Limits { count: 1, bytes: 10 });
        let (count, waker) = counter();
        let held = admitted(admission.admit(1, 10, &waker));
        assert!(matches!(admission.admit(2, 1, &waker), Admission::Full));

        admission.forget(2);
        drop(held);
        assert_eq!(woken(&count), 0);
    }

    /// Records whether the admission's lock was free when it was woken.
    struct Probe {
        limits: Arc<Shared>,
        free: AtomicBool,
    }

    impl Wake for Probe {
        fn wake(self: Arc<Probe>) {
            let free = self.limits.state.try_lock().is_ok();
            self.free.store(free, Ordering::Relaxed);
        }
    }

    // Both a release and a close wake with the lock released.
    #[test]
    fn wakers_run_outside_the_lock() {
        let admission = WriteAdmission::new(Limits { count: 1, bytes: 10 });
        let probe = Arc::new(Probe {
            limits: admission.0.clone(),
            free: AtomicBool::new(false),
        });
        let waker = Waker::from(probe.clone());
        let held = admitted(admission.admit(1, 10, &waker));

        assert!(matches!(admission.admit(2, 1, &waker), Admission::Full));
        drop(held);
        assert!(probe.free.swap(false, Ordering::Relaxed));

        let held = admitted(admission.admit(1, 10, &waker));
        assert!(matches!(admission.admit(2, 1, &waker), Admission::Full));
        admission.close();
        assert!(probe.free.load(Ordering::Relaxed));
        drop(held);
    }

    // Any sequence of admissions, refusals, releases and a close keeps the
    // counts equal to what the live permits hold and within the limits, and
    // wakes every waiter at the next release or close.
    #[test]
    fn the_counts_match_the_permits_and_no_waiter_is_lost() {
        fn property(steps: Vec<(u8, u8)>) -> bool {
            let limits = Limits { count: 3, bytes: 8 };
            let raw = request_limits(limits);
            let admission = WriteAdmission::new(limits);
            let counts: Vec<_> = (0..3).map(|_| counter()).collect();
            let mut live: Vec<WritePermit> = Vec::new();
            // Each waiting registration, with its wakes when it began to wait.
            let mut waiting: HashMap<u64, usize> = HashMap::new();
            let mut closed = false;

            for (kind, value) in steps {
                let (messages, bytes) = usage(&admission);
                let len = usize::from(value % 9);
                let released = match kind % 4 {
                    0 => {
                        let registration = u64::from(value % 3);
                        let (count, waker) = &counts[registration as usize];
                        match admission.admit(registration, len, waker) {
                            Admission::Admitted(permit) => {
                                if closed {
                                    return false;
                                }
                                live.push(permit);
                            }
                            Admission::Full => {
                                if closed
                                    || messages < limits.count
                                        && bytes + len <= limits.bytes
                                {
                                    return false;
                                }
                                waiting
                                    .entry(registration)
                                    .or_insert_with(|| woken(count));
                            }
                            Admission::Closed => {
                                if !closed {
                                    return false;
                                }
                            }
                        }
                        false
                    }
                    1 => {
                        let fits =
                            messages < raw.count && bytes + len <= raw.bytes;
                        match admission.admit_raw(len) {
                            Admission::Admitted(permit) => {
                                if closed || !fits {
                                    return false;
                                }
                                live.push(permit);
                            }
                            Admission::Full => {
                                if closed || fits {
                                    return false;
                                }
                            }
                            Admission::Closed => {
                                if !closed {
                                    return false;
                                }
                            }
                        }
                        false
                    }
                    2 if !live.is_empty() => {
                        live.swap_remove(usize::from(value) % live.len());
                        true
                    }
                    2 => false,
                    _ => {
                        admission.close();
                        closed = true;
                        true
                    }
                };

                if released {
                    for (registration, before) in waiting.drain() {
                        if woken(&counts[registration as usize].0) <= before {
                            return false;
                        }
                    }
                }
                let (messages, bytes) = usage(&admission);
                if messages != live.len()
                    || bytes != live.iter().map(|permit| permit.bytes).sum()
                    || messages > limits.count
                    || bytes > limits.bytes
                    || closed && !admission.0.state().waiters.is_empty()
                {
                    return false;
                }
            }
            true
        }

        quickcheck::QuickCheck::new()
            .tests(if cfg!(miri) { 8 } else { 1000 })
            .quickcheck(property as fn(Vec<(u8, u8)>) -> bool);
    }
}
