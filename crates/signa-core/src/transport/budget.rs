/*!
Count and byte reservations owned by outstanding transport work.

The queue transfers the data and synchronizes ownership. These relaxed atomic
counters only enforce quotas. Count bounds metadata even for empty writes,
while bytes bound encoded content. A permit stays with the data through
batching and partial writes, and returns both quotas on completion or teardown.
*/

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use super::WriteLimits;

#[derive(Clone, Debug)]
pub(crate) struct Budget(Arc<Capacity>);

#[derive(Debug)]
struct Capacity {
    limits: WriteLimits,
    messages: AtomicUsize,
    bytes: AtomicUsize,
}

impl Budget {
    pub(crate) fn new(limits: WriteLimits) -> Budget {
        Budget(Arc::new(Capacity {
            limits,
            messages: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
        }))
    }

    pub(crate) fn is_idle(&self) -> bool {
        self.0.messages.load(Ordering::Relaxed) == 0
    }

    pub(crate) fn acquire(&self, bytes: usize) -> Option<Permit> {
        self.acquire_with_limits(bytes, self.0.limits)
    }

    // New requests leave a quarter of output capacity for transaction output
    // and rejection responses. Tiny limits round the reserve down to zero.
    pub(crate) fn acquire_request(&self, bytes: usize) -> Option<Permit> {
        self.acquire_with_limits(bytes, request_limits(self.0.limits))
    }

    fn acquire_with_limits(
        &self,
        bytes: usize,
        limits: WriteLimits,
    ) -> Option<Permit> {
        reserve(&self.0.messages, 1, limits.messages)?;
        let mut permit = Permit { budget: self.clone(), bytes: 0 };
        reserve(&self.0.bytes, bytes, limits.bytes)?;
        permit.bytes = bytes;
        Some(permit)
    }
}

pub(crate) fn request_limits(limits: WriteLimits) -> WriteLimits {
    WriteLimits {
        messages: limits.messages - limits.messages / 4,
        bytes: limits.bytes - limits.bytes / 4,
    }
}

#[derive(Debug)]
pub(crate) struct Permit {
    budget: Budget,
    bytes: usize,
}

impl Permit {
    /// Replaces the charged size without releasing the message slot.
    /// A failed growth leaves the original reservation intact.
    pub(crate) fn resize(&mut self, bytes: usize) -> Option<()> {
        if bytes > self.bytes {
            reserve(
                &self.budget.0.bytes,
                bytes - self.bytes,
                self.budget.0.limits.bytes,
            )?;
        } else {
            self.budget
                .0
                .bytes
                .fetch_sub(self.bytes - bytes, Ordering::Relaxed);
        }
        self.bytes = bytes;
        Some(())
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.budget.0.bytes.fetch_sub(self.bytes, Ordering::Relaxed);
        self.budget.0.messages.fetch_sub(1, Ordering::Relaxed);
    }
}

fn reserve(counter: &AtomicUsize, amount: usize, max: usize) -> Option<()> {
    let mut used = counter.load(Ordering::Relaxed);
    loop {
        let total = used.checked_add(amount).filter(|&total| total <= max)?;
        match counter.compare_exchange_weak(
            used,
            total,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Some(()),
            Err(actual) => used = actual,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_rejection_rolls_back_the_message_and_drop_returns_both() {
        let budget = Budget::new(WriteLimits { messages: 2, bytes: 3 });
        let first = budget.acquire(3).unwrap();

        assert!(budget.acquire(1).is_none());
        let empty = budget.acquire(0).unwrap();
        assert!(budget.acquire(0).is_none());

        drop(first);
        assert!(budget.acquire(3).is_some());
        drop(empty);
        assert_eq!(budget.0.messages.load(Ordering::Relaxed), 0);
        assert_eq!(budget.0.bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn resize_keeps_the_slot_and_failed_growth_keeps_the_bytes() {
        let budget = Budget::new(WriteLimits { messages: 1, bytes: 10 });
        let mut permit = budget.acquire(6).unwrap();
        assert_eq!(permit.resize(10), Some(()));
        assert_eq!(permit.resize(11), None);
        assert_eq!(budget.0.bytes.load(Ordering::Relaxed), 10);
        assert_eq!(permit.resize(3), Some(()));
        assert_eq!(budget.0.bytes.load(Ordering::Relaxed), 3);
        assert!(budget.acquire(0).is_none());
        drop(permit);
        assert!(budget.acquire(10).is_some());
        assert!(budget.is_idle());
    }

    #[test]
    fn zero_and_overflow_never_reserve_unavailable_capacity() {
        let budget =
            Budget::new(WriteLimits { messages: 0, bytes: usize::MAX });
        assert!(budget.acquire(0).is_none());
        let budget = Budget::new(WriteLimits { messages: 1, bytes: 0 });
        assert!(budget.acquire(1).is_none());
        assert!(budget.acquire(0).is_some());
        let counter = AtomicUsize::new(usize::MAX);
        assert!(reserve(&counter, 1, usize::MAX).is_none());
        assert_eq!(counter.load(Ordering::Relaxed), usize::MAX);
    }

    #[test]
    fn concurrent_reservations_stay_bounded_and_leave_no_charge() {
        let budget = Budget::new(WriteLimits { messages: 4, bytes: 9 });
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let budget = budget.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        if let Some(_permit) = budget.acquire(3) {
                            assert!(
                                budget.0.messages.load(Ordering::Relaxed) <= 4
                            );
                            assert!(
                                budget.0.bytes.load(Ordering::Relaxed) <= 9
                            );
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(budget.0.messages.load(Ordering::Relaxed), 0);
        assert_eq!(budget.0.bytes.load(Ordering::Relaxed), 0);
    }
}
