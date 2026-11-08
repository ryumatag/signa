/*!
The transaction tables.

A table keeps its entries in a `Vec` of slots and finds them through a
hashbrown `HashTable` of slot numbers, so each key is stored once, in its slot.
Everything else that refers to a transaction, the timer heap and the server
transaction handles held by the TU, holds an [`Id`], which is two `u32` and
`Copy`. A `HashMap` would keep the key in the bucket, and a clone of it in each
of those places.

A slot is reused once its entry is removed, and its generation goes up each
time, so the `Id` of a transaction that is gone finds nothing, even when a new
transaction has the slot by then. The generation wraps at `u32::MAX`, which
takes that many transactions through one slot while a stale `Id` is still
around. Driver-owned timer references expire within a transaction timeout.
Long-lived TU capabilities additionally match their original shared allocation
before changing an entry, so generation wrap cannot redirect one to a new
transaction.
*/

use std::hash::{BuildHasher, Hash};

use foldhash::fast::RandomState;
use hashbrown::HashTable;

/// Names an entry of a [`Table`] for as long as it is there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Id {
    slot: u32,
    generation: u32,
}

/// A table of transactions, keyed by what matches a message to one.
pub(super) struct Table<K, E> {
    /// The slot number of each entry, by the hash of its key.
    index: HashTable<u32>,
    slots: Vec<Option<(K, E)>>,
    /// The generation of each slot, which goes up when the slot is vacated.
    /// Kept beside the slots rather than in them, where each would take eight
    /// bytes with its padding.
    generations: Vec<u32>,
    /// The vacant slots.
    free: Vec<u32>,
    hasher: RandomState,
}

impl<K: Hash + Eq, E> Table<K, E> {
    pub(super) fn new() -> Table<K, E> {
        Table {
            index: HashTable::new(),
            slots: Vec::new(),
            generations: Vec::new(),
            free: Vec::new(),
            hasher: RandomState::default(),
        }
    }

    /// How many entries the table has.
    pub(super) fn len(&self) -> usize {
        self.index.len()
    }

    /// Returns each live entry with its id, in slot order.
    pub(super) fn iter(&self) -> impl Iterator<Item = (Id, &E)> {
        self.slots.iter().enumerate().filter_map(|(slot, value)| {
            value.as_ref().map(|(_, entry)| {
                (
                    Id {
                        slot: slot as u32,
                        generation: self.generations[slot],
                    },
                    entry,
                )
            })
        })
    }

    /// Returns the entry under `key` and its id, if there is one.
    pub(super) fn find(&self, key: &K) -> Option<(Id, &E)> {
        let slot = self.slot_of(key)?;
        let (_, entry) = self.slots[slot as usize].as_ref().expect("indexed");
        let generation = self.generations[slot as usize];

        Some((Id { slot, generation }, entry))
    }

    /// Returns an entry whose key hashes as `probe` does and satisfies
    /// `matches`, and its id.
    ///
    /// A CANCEL finds its target this way. The keys hash by branch alone, so
    /// the CANCEL's own key finds candidates of any method.
    pub(super) fn find_by(
        &self,
        probe: &K,
        mut matches: impl FnMut(&K) -> bool,
    ) -> Option<(Id, &E)> {
        let hash = self.hasher.hash_one(probe);
        let slots = &self.slots;
        let &slot =
            self.index.find(hash, |&slot| matches(key_of(slots, slot)))?;
        let (_, entry) = self.slots[slot as usize].as_ref().expect("indexed");

        Some((Id { slot, generation: self.generations[slot as usize] }, entry))
    }

    /// Returns the entry `id` names, or `None` once it is removed.
    pub(super) fn get(&self, id: Id) -> Option<&E> {
        if self.generations.get(id.slot as usize) != Some(&id.generation) {
            return None;
        }

        self.slots[id.slot as usize].as_ref().map(|(_, entry)| entry)
    }

    /// See [`Table::get`].
    pub(super) fn get_mut(&mut self, id: Id) -> Option<&mut E> {
        if self.generations.get(id.slot as usize) != Some(&id.generation) {
            return None;
        }

        self.slots[id.slot as usize].as_mut().map(|(_, entry)| entry)
    }

    /// Adds `entry` under `key`, which must not be in the table, and returns
    /// its id.
    ///
    /// A second entry under an equal key would be found by neither [`find`]
    /// nor the other's removal reliably, so the caller checks with [`find`]
    /// first.
    ///
    /// [`find`]: Table::find
    pub(super) fn insert(&mut self, key: K, entry: E) -> Id {
        debug_assert!(self.slot_of(&key).is_none(), "the key is in the table");

        let hash = self.hasher.hash_one(&key);
        let slot = match self.free.pop() {
            Some(slot) => {
                self.slots[slot as usize] = Some((key, entry));
                slot
            }
            None => {
                // The slots would take terabytes before this overflows.
                let slot =
                    u32::try_from(self.slots.len()).expect("fewer slots");
                self.slots.push(Some((key, entry)));
                self.generations.push(0);
                slot
            }
        };

        let (slots, hasher) = (&self.slots, &self.hasher);
        self.index.insert_unique(hash, slot, |&slot| {
            hasher.hash_one(key_of(slots, slot))
        });

        Id { slot, generation: self.generations[slot as usize] }
    }

    /// Removes the entry `id` names and returns it, or `None` once it is
    /// removed already.
    pub(super) fn remove(&mut self, id: Id) -> Option<E> {
        let generation = self.generations.get_mut(id.slot as usize)?;
        if *generation != id.generation {
            return None;
        }
        let (key, entry) = self.slots[id.slot as usize].take()?;
        *generation = generation.wrapping_add(1);

        let hash = self.hasher.hash_one(&key);
        match self.index.find_entry(hash, |&slot| slot == id.slot) {
            Ok(occupied) => {
                occupied.remove();
            }
            Err(_) => unreachable!("every occupied slot is indexed"),
        }
        self.free.push(id.slot);

        Some(entry)
    }

    /// The slot of the entry under `key`.
    fn slot_of(&self, key: &K) -> Option<u32> {
        let hash = self.hasher.hash_one(key);
        let slots = &self.slots;

        self.index.find(hash, |&slot| key_of(slots, slot) == key).copied()
    }
}

/// The key in `slot`, which the index says is occupied.
fn key_of<K, E>(slots: &[Option<(K, E)>], slot: u32) -> &K {
    let (key, _) =
        slots[slot as usize].as_ref().expect("an indexed slot is occupied");

    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_by_takes_a_predicate_under_the_probe_hash() {
        let mut table = Table::new();
        let a = table.insert("a", 1);
        table.insert("b", 2);

        assert_eq!(table.find_by(&"a", |key| *key == "a"), Some((a, &1)));
        assert_eq!(table.find_by(&"a", |key| *key == "b"), None);
        table.remove(a);
        assert_eq!(table.find_by(&"a", |_| true), None);
    }

    #[test]
    fn entries_are_found_by_key_and_by_id() {
        let mut table = Table::new();
        let a = table.insert("a", 1);
        let b = table.insert("b", 2);
        assert_eq!(table.len(), 2);

        assert_eq!(table.find(&"a"), Some((a, &1)));
        assert_eq!(table.find(&"b"), Some((b, &2)));
        assert_eq!(table.find(&"c"), None);
        assert_eq!(table.get(a), Some(&1));
        assert_eq!(table.get(b), Some(&2));

        *table.get_mut(b).unwrap() = 3;
        assert_eq!(table.get(b), Some(&3));
    }

    #[test]
    fn a_removed_id_finds_nothing_even_when_its_slot_is_reused() {
        let mut table = Table::new();
        let a = table.insert("a", 1);
        assert_eq!(table.remove(a), Some(1));
        assert_eq!(table.len(), 0);
        assert_eq!(table.find(&"a"), None);
        assert_eq!(table.get(a), None);
        assert_eq!(table.remove(a), None);

        let b = table.insert("b", 2);
        assert_eq!(b.slot, a.slot, "the slot is reused");
        assert_ne!(b, a);
        assert_eq!(table.get(a), None);
        assert_eq!(table.get_mut(a), None);
        assert_eq!(table.remove(a), None);
        assert_eq!(table.get(b), Some(&2));
        assert_eq!(table.find(&"b"), Some((b, &2)));
    }

    #[test]
    fn the_index_follows_the_slots_through_growth_and_churn() {
        let mut table = Table::new();
        let mut ids = Vec::new();
        for n in 0..1000u32 {
            ids.push(table.insert(n, n * 2));
        }
        for n in (0..1000u32).step_by(2) {
            assert_eq!(table.remove(ids[n as usize]), Some(n * 2));
        }
        for n in 1000..1500u32 {
            ids.push(table.insert(n, n * 2));
        }
        assert_eq!(table.len(), 1000);

        for n in 0..1500u32 {
            let found = table.find(&n);
            if n < 1000 && n % 2 == 0 {
                assert_eq!(found, None, "{n}");
                assert_eq!(table.get(ids[n as usize]), None, "{n}");
            } else {
                assert_eq!(found, Some((ids[n as usize], &(n * 2))), "{n}");
            }
        }
    }
}
