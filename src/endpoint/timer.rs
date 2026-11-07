/*!
Deadlines with bounded lazy invalidation.

Only the driver changes transaction deadlines. It inserts a new entry when a
deadline changes and lets old entries expire harmlessly. Compaction keeps
only the current deadline of each live transaction once the heap exceeds
twice the live table count plus a small allowance. The allowance amortizes
compaction when reliable transactions finish without retaining any entries.
The allocation also shrinks when the live tables become much smaller.
*/

use std::{cmp::Ordering, collections::BinaryHeap, time::Instant};

use super::table::Id;

const STALE_ALLOWANCE: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Key {
    Server(Id),
    Client(Id),
    Shutdown,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    at: Instant,
    key: Key,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Entry) -> bool {
        self.at == other.at
    }
}

impl Eq for Entry {}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Entry) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Entry) -> Ordering {
        other.at.cmp(&self.at)
    }
}

pub(super) struct TimerQueue {
    heap: BinaryHeap<Entry>,
    shutdown: Option<Instant>,
}

impl TimerQueue {
    pub(super) fn new() -> TimerQueue {
        TimerQueue { heap: BinaryHeap::new(), shutdown: None }
    }

    /// Transaction callers insert when their deadline changes.
    pub(super) fn push(&mut self, at: Instant, key: Key) {
        if key == Key::Shutdown {
            if self.shutdown.is_some_and(|current| current <= at) {
                return;
            }
            self.shutdown = Some(at);
        }
        self.heap.push(Entry { at, key });
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        self.heap.peek().map(|entry| entry.at)
    }

    pub(super) fn pop(&mut self) -> Option<Key> {
        self.heap.pop().map(|entry| entry.key)
    }

    /// Called before polling the next event, after all previous state changes.
    /// Filtering visits heap entries rather than every table slot. A table
    /// can have a large historical capacity but few live transactions.
    pub(super) fn compact(
        &mut self,
        live: usize,
        mut deadline: impl FnMut(Key) -> Option<Instant>,
    ) {
        let limit = live
            .saturating_add(usize::from(self.shutdown.is_some()))
            .saturating_mul(2)
            .saturating_add(STALE_ALLOWANCE);
        if self.heap.len() > limit {
            let mut entries = std::mem::take(&mut self.heap).into_vec();
            entries.retain(|entry| {
                let current = if entry.key == Key::Shutdown {
                    self.shutdown
                } else {
                    deadline(entry.key)
                };
                current == Some(entry.at)
            });

            // A deadline can move away and back, leaving otherwise-valid
            // copies. Keep one per key without allocating a second index.
            entries.sort_unstable_by_key(|entry| entry.key);
            entries.dedup_by_key(|entry| entry.key);
            self.heap = BinaryHeap::from(entries);
        }

        // Do this even without stale entries. Popping expired timers can empty
        // a large heap without ever triggering the length threshold above.
        if self.heap.capacity() > limit.saturating_mul(2) {
            self.heap.shrink_to(limit);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use quickcheck::QuickCheck;

    use super::*;
    use crate::endpoint::table::Table;

    #[test]
    fn earlier_deadlines_fire_first() {
        let mut table = Table::new();
        let id = table.insert(0, ());
        let start = Instant::now();
        let mut timers = TimerQueue::new();
        timers.push(start + Duration::from_secs(3), Key::Server(id));
        timers.push(start, Key::Client(id));
        timers.push(start + Duration::from_secs(2), Key::Shutdown);

        assert_eq!(timers.deadline(), Some(start));
        assert_eq!(timers.pop(), Some(Key::Client(id)));
        assert_eq!(timers.pop(), Some(Key::Shutdown));
        assert_eq!(timers.pop(), Some(Key::Server(id)));
        assert_eq!(timers.deadline(), None);
    }

    #[test]
    fn reused_slots_and_replaced_deadlines_do_not_survive_compaction() {
        let start = Instant::now();
        let mut table = Table::new();
        let old = table.insert(0, start);
        let mut timers = TimerQueue::new();
        timers.push(start, Key::Server(old));
        table.remove(old);
        let current = table.insert(1, start);
        timers.push(start, Key::Server(current));

        for n in 1..100 {
            let at = start + Duration::from_secs(n);
            *table.get_mut(current).unwrap() = at;
            timers.push(at, Key::Server(current));
        }
        timers.compact(table.len(), |key| match key {
            Key::Server(id) => table.get(id).copied(),
            _ => None,
        });

        assert_eq!(timers.heap.len(), 1);
        assert_eq!(timers.deadline(), table.get(current).copied());
        assert_eq!(timers.pop(), Some(Key::Server(current)));
    }

    #[test]
    fn shutdown_keeps_only_the_earliest_intent_after_compaction() {
        let start = Instant::now();
        let mut timers = TimerQueue::new();
        for n in (0..100).rev() {
            timers.push(start + Duration::from_secs(n), Key::Shutdown);
        }
        timers.push(start + Duration::from_secs(200), Key::Shutdown);
        timers.compact(0, |_| None);

        assert_eq!(timers.heap.len(), 1);
        assert_eq!(timers.deadline(), Some(start));
        assert_eq!(timers.pop(), Some(Key::Shutdown));
    }

    #[test]
    fn compaction_preserves_both_tables_and_shutdown_in_deadline_order() {
        let start = Instant::now();
        let mut servers = Table::new();
        let mut clients = Table::new();
        let server = servers.insert(0, start + Duration::from_secs(2));
        let client = clients.insert(0, start);
        assert_eq!(server, client, "IDs are local to each table");
        let mut timers = TimerQueue::new();
        timers.push(start, Key::Client(client));
        timers.push(start + Duration::from_secs(1), Key::Shutdown);
        timers.push(start + Duration::from_secs(2), Key::Server(server));
        for n in 3..100 {
            timers.push(start + Duration::from_secs(n), Key::Client(client));
        }

        timers.compact(servers.len() + clients.len(), |key| match key {
            Key::Server(id) => servers.get(id).copied(),
            Key::Client(id) => clients.get(id).copied(),
            Key::Shutdown => unreachable!("the queue owns shutdown"),
        });

        assert_eq!(timers.heap.len(), 3);
        assert_eq!(timers.pop(), Some(Key::Client(client)));
        assert_eq!(timers.pop(), Some(Key::Shutdown));
        assert_eq!(timers.pop(), Some(Key::Server(server)));
    }

    #[test]
    fn returning_to_a_deadline_keeps_only_one_current_copy() {
        let mut table = Table::new();
        let id = table.insert(0, ());
        let start = Instant::now();
        let mut timers = TimerQueue::new();
        for n in 0..100 {
            timers.push(start + Duration::from_secs(n % 2), Key::Client(id));
        }

        timers.compact(1, |_| Some(start));

        assert_eq!(timers.heap.len(), 1);
        assert_eq!(timers.deadline(), Some(start));
        assert_eq!(timers.pop(), Some(Key::Client(id)));
    }

    #[test]
    fn allocation_shrinks_after_timers_expire_without_stale_entries() {
        let mut table = Table::new();
        let id = table.insert(0, ());
        let mut timers = TimerQueue::new();
        for n in 0..1024 {
            timers.push(
                Instant::now() + Duration::from_secs(n),
                Key::Client(id),
            );
        }
        assert!(timers.heap.capacity() >= 1024);
        while timers.pop().is_some() {}

        timers.compact(0, |_| None);

        assert!(timers.heap.capacity() <= 2 * STALE_ALLOWANCE);
    }

    #[test]
    fn arbitrary_deadline_changes_preserve_live_timers_and_bound_history() {
        fn property(changes: Vec<(u8, u16)>) -> bool {
            let start = Instant::now();
            let mut table = Table::new();
            let ids: Vec<_> = (0..8).map(|n| table.insert(n, None)).collect();
            let mut timers = TimerQueue::new();
            for (index, time) in changes {
                let id = ids[usize::from(index) % ids.len()];
                let at = (time != 0)
                    .then(|| start + Duration::from_millis(u64::from(time)));
                let current = table.get_mut(id).unwrap();
                if *current != at {
                    *current = at;
                    if let Some(at) = at {
                        timers.push(at, Key::Client(id));
                    }
                }
                timers.compact(table.len(), |key| match key {
                    Key::Client(id) => table.get(id).copied().flatten(),
                    _ => None,
                });
                let limit = 2 * table.len() + STALE_ALLOWANCE;
                if timers.heap.len() > limit
                    || timers.heap.capacity() > 2 * limit
                {
                    return false;
                }
            }

            for id in ids {
                if let Some(at) = *table.get(id).unwrap() {
                    if !timers.heap.iter().any(|entry| {
                        entry.key == Key::Client(id) && entry.at == at
                    }) {
                        return false;
                    }
                }
            }
            true
        }

        QuickCheck::new()
            .tests(if cfg!(miri) { 8 } else { 100 })
            .quickcheck(property as fn(Vec<(u8, u16)>) -> bool);
    }
}
