/*!
Tables of records addressed by generation-checked keys.

Commands, timers and I/O results reach the model after it may have moved on.
An attempt can finish while a timer for it is still queued, and its slot can
then hold a new attempt. Each slot therefore carries a generation that changes
whenever its record is removed, and a key names both. A key from an earlier
generation finds nothing, so a late input cannot touch the record that took its
slot.
*/

use std::{fmt, hash::Hash, marker::PhantomData};

/// The address of a record in a [`Slots<T>`].
///
/// The type parameter keeps the key of one table from being used in another.
pub(crate) struct Key<T> {
    index: u32,
    generation: u32,
    record: PhantomData<fn() -> T>,
}

// Derives would require `T` to implement each trait, though the key holds no
// `T`.
impl<T> Clone for Key<T> {
    fn clone(&self) -> Key<T> {
        *self
    }
}

impl<T> Copy for Key<T> {}

impl<T> PartialEq for Key<T> {
    fn eq(&self, other: &Key<T>) -> bool {
        self.index == other.index && self.generation == other.generation
    }
}

impl<T> Eq for Key<T> {}

impl<T> Hash for Key<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (self.index, self.generation).hash(state);
    }
}

impl<T> fmt::Debug for Key<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}v{}", self.index, self.generation)
    }
}

/// A bounded table whose keys go stale when their record is removed.
pub(crate) struct Slots<T> {
    entries: Vec<Entry<T>>,
    /// Vacant slots that can be reused, the most recently freed last.
    free: Vec<u32>,
    len: usize,
    /// Slots promised to [`Slots::insert_reserved`], which `insert` leaves
    /// alone.
    reserved: usize,
    limit: usize,
}

enum Entry<T> {
    Occupied {
        generation: u32,
        value: T,
    },
    Vacant {
        generation: u32,
    },
    /// A slot whose generation ran out. It is never reused, so that no key can
    /// come back to life after the counter wraps.
    Retired,
}

impl<T> Slots<T> {
    /// Creates a table that holds at most `limit` records.
    pub(crate) fn new(limit: usize) -> Slots<T> {
        Slots {
            entries: Vec::new(),
            free: Vec::new(),
            len: 0,
            reserved: 0,
            limit,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Stores `value`, or hands it back when the table is full.
    pub(crate) fn insert(&mut self, value: T) -> Result<Key<T>, T> {
        if self.len + self.reserved >= self.limit {
            return Err(value);
        }

        self.store(value)
    }

    /// Sets a slot aside for a later [`Slots::insert_reserved`], so that work
    /// committed in between cannot take it. Returns whether there was room.
    pub(crate) fn reserve(&mut self) -> bool {
        if self.len + self.reserved >= self.limit {
            return false;
        }

        self.reserved += 1;
        true
    }

    /// Gives back a slot set aside by [`Slots::reserve`].
    pub(crate) fn release(&mut self) {
        debug_assert!(self.reserved > 0, "a slot was reserved");
        self.reserved = self.reserved.saturating_sub(1);
    }

    /// Stores `value` in a slot set aside by [`Slots::reserve`].
    pub(crate) fn insert_reserved(&mut self, value: T) -> Key<T> {
        self.release();
        let Ok(key) = self.store(value) else {
            panic!("a reserved slot fits unless u32::MAX slots retired");
        };
        key
    }

    fn store(&mut self, value: T) -> Result<Key<T>, T> {
        let (index, generation) = match self.free.pop() {
            Some(index) => {
                let entry = &mut self.entries[index as usize];
                let Entry::Vacant { generation } = *entry else {
                    unreachable!("the free list holds only vacant slots");
                };
                *entry = Entry::Occupied { generation, value };
                (index, generation)
            }
            None => {
                let Ok(index) = u32::try_from(self.entries.len()) else {
                    return Err(value);
                };
                self.entries.push(Entry::Occupied { generation: 0, value });
                (index, 0)
            }
        };

        self.len += 1;
        Ok(Key { index, generation, record: PhantomData })
    }

    pub(crate) fn get(&self, key: Key<T>) -> Option<&T> {
        match self.entries.get(key.index as usize)? {
            Entry::Occupied { generation, value }
                if *generation == key.generation =>
            {
                Some(value)
            }
            _ => None,
        }
    }

    pub(crate) fn get_mut(&mut self, key: Key<T>) -> Option<&mut T> {
        match self.entries.get_mut(key.index as usize)? {
            Entry::Occupied { generation, value }
                if *generation == key.generation =>
            {
                Some(value)
            }
            _ => None,
        }
    }

    /// Removes the record of `key` and makes every copy of the key stale.
    pub(crate) fn remove(&mut self, key: Key<T>) -> Option<T> {
        let entry = self.entries.get_mut(key.index as usize)?;
        match entry {
            Entry::Occupied { generation, .. }
                if *generation == key.generation => {}
            _ => return None,
        }

        let next = match key.generation.checked_add(1) {
            Some(generation) => Entry::Vacant { generation },
            None => Entry::Retired,
        };
        let Entry::Occupied { value, .. } = std::mem::replace(entry, next)
        else {
            unreachable!("the entry was checked to be occupied");
        };
        if matches!(entry, Entry::Vacant { .. }) {
            self.free.push(key.index);
        }

        self.len -= 1;
        Some(value)
    }

    /// Returns the keys and records in the table, in slot order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (Key<T>, &T)> {
        self.entries.iter().enumerate().filter_map(
            |(index, entry)| match entry {
                Entry::Occupied { generation, value } => Some((
                    Key {
                        // The table never grows past `u32::MAX` slots.
                        index: index as u32,
                        generation: *generation,
                        record: PhantomData,
                    },
                    value,
                )),
                _ => None,
            },
        )
    }

    /// Returns the keys and records in the table, in slot order, for change.
    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (Key<T>, &mut T)> {
        self.entries.iter_mut().enumerate().filter_map(|(index, entry)| {
            match entry {
                Entry::Occupied { generation, value } => Some((
                    Key {
                        // The table never grows past `u32::MAX` slots.
                        index: index as u32,
                        generation: *generation,
                        record: PhantomData,
                    },
                    value,
                )),
                _ => None,
            }
        })
    }
}

impl<T: fmt::Debug> fmt::Debug for Slots<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_generation_cannot_mutate_reused_slot() {
        let mut slots = Slots::new(1);
        let stale = slots.insert("first").unwrap();
        slots.remove(stale).unwrap();
        let fresh = slots.insert("second").unwrap();

        assert_eq!(stale.index, fresh.index);
        assert_ne!(stale, fresh);
        assert!(slots.get(stale).is_none());
        assert!(slots.get_mut(stale).is_none());
        assert!(slots.remove(stale).is_none());
        assert_eq!(slots.get(fresh), Some(&"second"));
    }

    #[test]
    fn a_full_table_hands_the_value_back() {
        let mut slots = Slots::new(1);
        slots.insert(1).unwrap();

        assert_eq!(slots.insert(2), Err(2));
        assert_eq!(slots.len(), 1);
    }

    #[test]
    fn a_reservation_keeps_its_slot() {
        let mut slots = Slots::new(2);
        assert!(slots.reserve());
        slots.insert(1).unwrap();

        assert!(!slots.reserve());
        assert_eq!(slots.insert(2), Err(2));
        let key = slots.insert_reserved(3);
        assert_eq!(slots.get(key), Some(&3));

        slots.remove(key);
        assert!(slots.reserve());
        slots.release();
        assert_eq!(slots.len(), 1);
        slots.insert(4).unwrap();
    }

    #[test]
    fn a_slot_whose_generation_runs_out_is_retired() {
        let mut slots = Slots::new(2);
        let last = slots.insert(()).unwrap();
        slots.entries[last.index as usize] =
            Entry::Occupied { generation: u32::MAX, value: () };
        let last = Key { generation: u32::MAX, ..last };

        slots.remove(last).unwrap();
        let next = slots.insert(()).unwrap();

        assert_ne!(next.index, last.index);
        assert!(slots.get(last).is_none());
    }
}
