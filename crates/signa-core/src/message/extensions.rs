/*!
A type map for extra data on SIP messages.

Adapted from the `Extensions` type in the `http` crate.
*/

use std::{
    any::{Any, TypeId, type_name},
    collections::HashMap,
    fmt,
    hash::{BuildHasherDefault, Hasher},
};

type AnyMap = HashMap<
    TypeId,
    Box<dyn AnyClone + Send + Sync>,
    BuildHasherDefault<IdHasher>,
>;

// A `TypeId` is already a hash computed by the compiler, so hashing it again
// is wasted work. `IdHasher` keeps the `u64` that `TypeId` writes and returns
// it as is.
#[derive(Default)]
struct IdHasher(u64);

impl Hasher for IdHasher {
    // `TypeId` currently hashes itself with a single `write_u64`, so this is
    // not called. The `http` crate panics here. I mix the bytes in instead so
    // that a change to `TypeId`'s `Hash` impl only costs speed, not
    // correctness.
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(byte);
        }
    }

    #[inline]
    fn write_u64(&mut self, id: u64) {
        self.0 = id;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

/// A type map of extra data attached to a SIP message.
///
/// A request or response can carry values of any type that is `Clone + Send +
/// Sync + 'static`, at most one per type. Layers that handle the message use
/// this to pass along data that is not part of the message itself, such as
/// where it was received from.
///
/// # Example
///
/// ```
/// use signa_core::Extensions;
///
/// #[derive(Clone, Debug, PartialEq)]
/// struct ReceivedFrom(std::net::SocketAddr);
///
/// let mut extensions = Extensions::new();
/// extensions.insert(ReceivedFrom("192.0.2.4:5060".parse().unwrap()));
///
/// let from = extensions.get::<ReceivedFrom>().unwrap();
/// assert_eq!(from.0.port(), 5060);
/// ```
#[derive(Clone, Default)]
pub struct Extensions {
    // Most messages carry no extensions. `None` keeps an empty map at one word
    // and avoids allocating until something is inserted.
    map: Option<Box<AnyMap>>,
}

impl Extensions {
    /// Creates an empty `Extensions`.
    ///
    /// This does not allocate.
    #[inline]
    pub const fn new() -> Extensions {
        Extensions { map: None }
    }

    /// Inserts `value`, returning the previous value of the same type.
    ///
    /// # Example
    ///
    /// ```
    /// use signa_core::Extensions;
    ///
    /// let mut extensions = Extensions::new();
    /// assert!(extensions.insert(5i32).is_none());
    /// assert!(extensions.insert(4u8).is_none());
    /// assert_eq!(extensions.insert(9i32), Some(5i32));
    /// ```
    pub fn insert<T: Clone + Send + Sync + 'static>(
        &mut self,
        value: T,
    ) -> Option<T> {
        self.map
            .get_or_insert_with(Box::default)
            .insert(TypeId::of::<T>(), Box::new(value))
            .and_then(|boxed| {
                boxed.into_any().downcast().ok().map(|boxed| *boxed)
            })
    }

    /// Returns a reference to the value of type `T`, if present.
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.map
            .as_ref()
            .and_then(|map| map.get(&TypeId::of::<T>()))
            .and_then(|boxed| (**boxed).as_any().downcast_ref())
    }

    /// Returns a mutable reference to the value of type `T`, if present.
    pub fn get_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.map
            .as_mut()
            .and_then(|map| map.get_mut(&TypeId::of::<T>()))
            .and_then(|boxed| (**boxed).as_any_mut().downcast_mut())
    }

    /// Returns a mutable reference to the value of type `T`, inserting `value`
    /// first if there is none.
    pub fn get_or_insert<T: Clone + Send + Sync + 'static>(
        &mut self,
        value: T,
    ) -> &mut T {
        self.get_or_insert_with(|| value)
    }

    /// Returns a mutable reference to the value of type `T`, inserting the
    /// result of `f` first if there is none.
    ///
    /// # Example
    ///
    /// ```
    /// use signa_core::Extensions;
    ///
    /// let mut extensions = Extensions::new();
    /// *extensions.get_or_insert_with(|| 1i32) += 2;
    /// assert_eq!(extensions.get::<i32>(), Some(&3));
    /// ```
    pub fn get_or_insert_with<T, F>(&mut self, f: F) -> &mut T
    where
        T: Clone + Send + Sync + 'static,
        F: FnOnce() -> T,
    {
        let boxed = self
            .map
            .get_or_insert_with(Box::default)
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::new(f()));
        (**boxed)
            .as_any_mut()
            .downcast_mut()
            .expect("the entry for `TypeId::of::<T>()` always holds a `T`")
    }

    /// Returns a mutable reference to the value of type `T`, inserting
    /// `T::default()` first if there is none.
    pub fn get_or_insert_default<T>(&mut self) -> &mut T
    where
        T: Default + Clone + Send + Sync + 'static,
    {
        self.get_or_insert_with(T::default)
    }

    /// Removes and returns the value of type `T`, if present.
    pub fn remove<T: Send + Sync + 'static>(&mut self) -> Option<T> {
        self.map
            .as_mut()
            .and_then(|map| map.remove(&TypeId::of::<T>()))
            .and_then(|boxed| {
                boxed.into_any().downcast().ok().map(|boxed| *boxed)
            })
    }

    /// Removes every value, keeping the allocated map.
    #[inline]
    pub fn clear(&mut self) {
        if let Some(map) = &mut self.map {
            map.clear();
        }
    }

    /// Returns `true` if there are no values.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of values.
    #[inline]
    pub fn len(&self) -> usize {
        self.map.as_ref().map_or(0, |map| map.len())
    }

    /// Moves every value from `other` into `self`.
    ///
    /// A value in `other` replaces a value of the same type in `self`.
    ///
    /// # Example
    ///
    /// ```
    /// use signa_core::Extensions;
    ///
    /// let mut a = Extensions::new();
    /// a.insert(8u8);
    /// a.insert(16u16);
    ///
    /// let mut b = Extensions::new();
    /// b.insert(4u8);
    /// b.insert("hello");
    ///
    /// a.extend(b);
    /// assert_eq!(a.len(), 3);
    /// assert_eq!(a.get::<u8>(), Some(&4));
    /// assert_eq!(a.get::<u16>(), Some(&16));
    /// assert_eq!(a.get::<&str>(), Some(&"hello"));
    /// ```
    pub fn extend(&mut self, other: Extensions) {
        let Some(other) = other.map else { return };

        match &mut self.map {
            Some(map) => map.extend(*other),
            None => self.map = Some(other),
        }
    }
}

impl fmt::Debug for Extensions {
    /// Lists the type names of the stored values. The values themselves need
    /// not implement `Debug`, so they are not shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct TypeName(&'static str);

        impl fmt::Debug for TypeName {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0)
            }
        }

        let mut set = f.debug_set();
        if let Some(map) = &self.map {
            // Dereference to the `dyn AnyClone` first. The box itself also
            // implements `AnyClone` through the blanket impl, and calling the
            // method on it would name `Box<dyn AnyClone>` instead.
            set.entries(
                map.values().map(|boxed| TypeName((**boxed).type_name())),
            );
        }
        set.finish()
    }
}

// Object-safe access to a stored value, including cloning it, which `Any`
// alone does not offer.
trait AnyClone: Any {
    fn clone_box(&self) -> Box<dyn AnyClone + Send + Sync>;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
    fn type_name(&self) -> &'static str;
}

impl<T: Clone + Send + Sync + 'static> AnyClone for T {
    fn clone_box(&self) -> Box<dyn AnyClone + Send + Sync> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }

    fn type_name(&self) -> &'static str {
        type_name::<T>()
    }
}

impl Clone for Box<dyn AnyClone + Send + Sync> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

#[cfg(test)]
mod tests {
    use std::hash::Hash;

    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    struct Transport(&'static str);

    #[test]
    fn new_is_empty() {
        let extensions = Extensions::new();
        assert!(extensions.is_empty());
        assert_eq!(extensions.len(), 0);
        assert_eq!(extensions.get::<i32>(), None);
        assert_eq!(format!("{extensions:?}"), "{}");
    }

    #[test]
    fn one_value_per_type() {
        let mut extensions = Extensions::new();
        assert_eq!(extensions.insert(Transport("udp")), None);
        assert_eq!(extensions.insert(5i32), None);
        assert_eq!(
            extensions.insert(Transport("tcp")),
            Some(Transport("udp"))
        );

        assert_eq!(extensions.len(), 2);
        assert_eq!(extensions.get(), Some(&Transport("tcp")));
        assert_eq!(extensions.get(), Some(&5i32));
    }

    #[test]
    fn get_mut_and_remove() {
        let mut extensions = Extensions::new();
        extensions.insert(String::from("Hello"));
        extensions.get_mut::<String>().unwrap().push_str(" World");
        assert_eq!(extensions.get::<String>().unwrap(), "Hello World");

        assert_eq!(extensions.remove::<String>().unwrap(), "Hello World");
        assert_eq!(extensions.remove::<String>(), None);
        assert!(extensions.is_empty());
    }

    #[test]
    fn get_or_insert_variants() {
        let mut extensions = Extensions::new();
        *extensions.get_or_insert(1i32) += 1;
        *extensions.get_or_insert(10i32) += 1;
        assert_eq!(extensions.get::<i32>(), Some(&3));

        *extensions.get_or_insert_default::<u8>() += 2;
        assert_eq!(extensions.get::<u8>(), Some(&2));
    }

    #[test]
    fn clones_are_independent() {
        let mut extensions = Extensions::new();
        extensions.insert(Transport("udp"));

        let copy = extensions.clone();
        extensions.insert(Transport("tcp"));

        assert_eq!(copy.get(), Some(&Transport("udp")));
        assert_eq!(extensions.get(), Some(&Transport("tcp")));
    }

    #[test]
    fn extend_into_empty_and_clear() {
        let mut target = Extensions::new();
        let mut source = Extensions::new();
        source.insert(Transport("udp"));

        target.extend(source);
        target.extend(Extensions::new());
        assert_eq!(target.get(), Some(&Transport("udp")));

        target.clear();
        assert!(target.is_empty());
    }

    #[test]
    fn debug_lists_type_names() {
        let mut extensions = Extensions::new();
        extensions.insert(5i32);
        assert_eq!(format!("{extensions:?}"), "{i32}");
    }

    #[test]
    fn id_hasher_keeps_written_u64() {
        let mut hasher = IdHasher::default();
        hasher.write_u64(0x1234);
        assert_eq!(hasher.finish(), 0x1234);

        // Whatever `TypeId` writes, distinct types should not all collide.
        let hash = |id: TypeId| {
            let mut hasher = IdHasher::default();
            id.hash(&mut hasher);
            hasher.finish()
        };
        assert_ne!(hash(TypeId::of::<i32>()), hash(TypeId::of::<u8>()));
    }
}
