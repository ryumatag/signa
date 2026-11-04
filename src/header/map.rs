use std::{borrow::Cow, fmt, iter::FusedIterator, slice, vec};

use super::{HeaderName, HeaderValue};

pub use self::as_header_name::AsHeaderName;

/// A multimap of SIP header fields that keeps their order.
///
/// Every header field row is kept in the order it was added, so iterating
/// over a map built from a received message yields the rows in wire order.
/// A name may appear in several rows. [`HeaderMap::get_all`] returns their
/// values in order, which matters for fields such as `Via` and `Route`.
///
/// [RFC 3261 section 7.3.1] only gives meaning to the relative order of
/// rows with the same name. I still keep the order across names because a
/// message that is forwarded or logged should look like the one received,
/// and because the RFC recommends putting fields that proxies need, such
/// as `Via` and `Route`, near the top.
///
/// Lookups scan the rows, so they take time linear in the number of rows.
/// A SIP head has few rows, and comparing two standard header names is a
/// single enum comparison, so I expect a scan to be at least as fast as
/// hashing at these sizes. The number of rows in a received head is bounded
/// when it is parsed.
///
/// Header names compare as [`HeaderName`] does. Lookups are therefore
/// case-insensitive, and a compact form such as `v` finds `Via` rows.
///
/// ```
/// use signa::header::{HeaderMap, HeaderValue, CALL_ID, VIA};
///
/// let mut headers = HeaderMap::new();
/// headers.append(VIA, HeaderValue::from_static("SIP/2.0/UDP a.example.com"));
/// headers.append(CALL_ID, HeaderValue::from_static("a84b4c76e66710"));
/// headers.append(VIA, HeaderValue::from_static("SIP/2.0/UDP b.example.com"));
///
/// let vias: Vec<_> = headers.get_all("v").collect();
/// assert_eq!(vias, ["SIP/2.0/UDP a.example.com", "SIP/2.0/UDP b.example.com"]);
/// assert_eq!(headers.get("call-id").unwrap(), "a84b4c76e66710");
/// ```
///
/// `HeaderMap` does not implement `PartialEq`. Exact row order is stricter
/// than SIP's notion of equivalent headers, while comparing per name would
/// hide reordering that callers may care about. Compare
/// [`HeaderMap::iter`] or [`HeaderMap::get_all`] output instead.
///
/// [RFC 3261 section 7.3.1]: https://www.rfc-editor.org/rfc/rfc3261#section-7.3.1
#[derive(Clone, Default)]
pub struct HeaderMap {
    rows: Vec<(HeaderName, HeaderValue)>,
}

impl HeaderMap {
    /// Creates an empty `HeaderMap`.
    ///
    /// This does not allocate.
    pub const fn new() -> HeaderMap {
        HeaderMap { rows: Vec::new() }
    }

    /// Creates an empty `HeaderMap` with room for at least `capacity` rows.
    pub fn with_capacity(capacity: usize) -> HeaderMap {
        HeaderMap { rows: Vec::with_capacity(capacity) }
    }

    /// Returns the number of rows, counting each value of a repeated name.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Returns `true` if the map has no rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Returns the number of rows the map can hold without reallocating.
    pub fn capacity(&self) -> usize {
        self.rows.capacity()
    }

    /// Reserves room for at least `additional` more rows.
    pub fn reserve(&mut self, additional: usize) {
        self.rows.reserve(additional);
    }

    /// Removes every row, keeping the allocated capacity.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Returns `true` if the map has a row with `name`.
    pub fn contains_key<K: AsHeaderName>(&self, name: K) -> bool {
        self.get(name).is_some()
    }

    /// Returns the value of the first row with `name`.
    ///
    /// Use [`HeaderMap::get_all`] for names that may appear in several rows.
    pub fn get<K: AsHeaderName>(&self, name: K) -> Option<&HeaderValue> {
        let name = name.to_header_name()?;
        self.position(&name).map(|i| &self.rows[i].1)
    }

    /// Returns a mutable reference to the value of the first row with `name`.
    pub fn get_mut<K: AsHeaderName>(
        &mut self,
        name: K,
    ) -> Option<&mut HeaderValue> {
        let name = name.to_header_name()?;
        let i = self.position(&name)?;
        Some(&mut self.rows[i].1)
    }

    /// Returns the values of every row with `name`, in order.
    pub fn get_all<K: AsHeaderName>(&self, name: K) -> GetAll<'_> {
        GetAll {
            name: name.to_header_name().map(Cow::into_owned),
            rows: self.rows.iter(),
        }
    }

    /// Sets `name` to the single value `value`.
    ///
    /// If rows with `name` exist, `value` replaces the first of them in
    /// place and the others are removed. The first previous value is
    /// returned. Otherwise a new row is added at the end and this returns
    /// `None`.
    pub fn insert(
        &mut self,
        name: HeaderName,
        value: HeaderValue,
    ) -> Option<HeaderValue> {
        let Some(first) = self.position(&name) else {
            self.rows.push((name, value));
            return None;
        };

        let previous = std::mem::replace(&mut self.rows[first].1, value);

        // `retain` visits rows in order, so the index tells the kept first
        // row apart from later rows with the same name.
        let mut index = 0;
        self.rows.retain(|(row_name, _)| {
            let keep = index <= first || *row_name != name;
            index += 1;
            keep
        });

        Some(previous)
    }

    /// Adds a row with `name` and `value` at the end.
    ///
    /// Existing rows with `name` are kept, and the new value comes after
    /// them. Returns `true` if rows with `name` already existed.
    pub fn append(&mut self, name: HeaderName, value: HeaderValue) -> bool {
        let existed = self.position(&name).is_some();
        self.rows.push((name, value));
        existed
    }

    /// Removes every row with `name` and returns the first removed value.
    pub fn remove<K: AsHeaderName>(&mut self, name: K) -> Option<HeaderValue> {
        let name = name.to_header_name()?;
        let first = self.position(&name)?;
        let (_, value) = self.rows.remove(first);
        self.rows.retain(|(row_name, _)| *row_name != *name);
        Some(value)
    }

    /// Returns an iterator over every row, in order.
    pub fn iter(&self) -> Iter<'_> {
        Iter(self.rows.iter())
    }

    fn position(&self, name: &HeaderName) -> Option<usize> {
        self.rows.iter().position(|(row_name, _)| row_name == name)
    }
}

impl fmt::Debug for HeaderMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<'a> IntoIterator for &'a HeaderMap {
    type Item = (&'a HeaderName, &'a HeaderValue);
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl IntoIterator for HeaderMap {
    type Item = (HeaderName, HeaderValue);
    type IntoIter = IntoIter;

    fn into_iter(self) -> IntoIter {
        IntoIter(self.rows.into_iter())
    }
}

impl FromIterator<(HeaderName, HeaderValue)> for HeaderMap {
    /// Collects rows in order. Repeated names become separate rows, as with
    /// [`HeaderMap::append`].
    fn from_iter<I>(iter: I) -> HeaderMap
    where
        I: IntoIterator<Item = (HeaderName, HeaderValue)>,
    {
        HeaderMap { rows: iter.into_iter().collect() }
    }
}

impl Extend<(HeaderName, HeaderValue)> for HeaderMap {
    /// Appends rows in order, as with [`HeaderMap::append`].
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (HeaderName, HeaderValue)>,
    {
        self.rows.extend(iter);
    }
}

/// An iterator over the rows of a [`HeaderMap`], in order.
///
/// This is created by [`HeaderMap::iter`].
#[derive(Clone, Debug)]
pub struct Iter<'a>(slice::Iter<'a, (HeaderName, HeaderValue)>);

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a HeaderName, &'a HeaderValue);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(name, value)| (name, value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl DoubleEndedIterator for Iter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back().map(|(name, value)| (name, value))
    }
}

impl ExactSizeIterator for Iter<'_> {}

impl FusedIterator for Iter<'_> {}

/// An owning iterator over the rows of a [`HeaderMap`], in order.
///
/// This is created by the `IntoIterator` implementation of [`HeaderMap`].
#[derive(Debug)]
pub struct IntoIter(vec::IntoIter<(HeaderName, HeaderValue)>);

impl Iterator for IntoIter {
    type Item = (HeaderName, HeaderValue);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl DoubleEndedIterator for IntoIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back()
    }
}

impl ExactSizeIterator for IntoIter {}

impl FusedIterator for IntoIter {}

/// An iterator over the values of every row with one name, in order.
///
/// This is created by [`HeaderMap::get_all`].
#[derive(Clone, Debug)]
pub struct GetAll<'a> {
    // `None` when the name passed to `get_all` is not a valid header name.
    // No row can match it, so the iterator is empty.
    name: Option<HeaderName>,
    rows: slice::Iter<'a, (HeaderName, HeaderValue)>,
}

impl<'a> Iterator for GetAll<'a> {
    type Item = &'a HeaderValue;

    fn next(&mut self) -> Option<&'a HeaderValue> {
        let name = self.name.as_ref()?;
        self.rows
            .by_ref()
            .find(|(row_name, _)| row_name == name)
            .map(|(_, value)| value)
    }
}

impl DoubleEndedIterator for GetAll<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let name = self.name.as_ref()?;
        self.rows
            .by_ref()
            .rfind(|(row_name, _)| row_name == name)
            .map(|(_, value)| value)
    }
}

impl FusedIterator for GetAll<'_> {}

mod as_header_name {
    use std::borrow::Cow;

    use super::HeaderName;

    /// A type that can name the rows to look up in a
    /// [`HeaderMap`](super::HeaderMap).
    ///
    /// This is implemented for [`HeaderName`] and for strings. A string that
    /// is not a valid header name matches no rows. Looking up a custom
    /// (non-standard) name by string allocates to normalize it.
    ///
    /// This trait is sealed and cannot be implemented outside of `signa`.
    pub trait AsHeaderName: Sealed {}

    // The conversion lives on this hidden supertrait rather than on
    // `AsHeaderName`, so that callers cannot use it and I can change it
    // without breaking anyone. `unreachable_pub` is allowed because a sealed
    // supertrait has to be `pub` to appear in a public trait's bounds.
    #[allow(unreachable_pub)]
    pub trait Sealed {
        #[doc(hidden)]
        fn to_header_name(&self) -> Option<Cow<'_, HeaderName>>;
    }

    fn parse(src: &str) -> Option<Cow<'static, HeaderName>> {
        HeaderName::from_bytes(src.as_bytes()).ok().map(Cow::Owned)
    }

    impl Sealed for HeaderName {
        fn to_header_name(&self) -> Option<Cow<'_, HeaderName>> {
            Some(Cow::Borrowed(self))
        }
    }

    impl AsHeaderName for HeaderName {}

    impl Sealed for &HeaderName {
        fn to_header_name(&self) -> Option<Cow<'_, HeaderName>> {
            Some(Cow::Borrowed(*self))
        }
    }

    impl AsHeaderName for &HeaderName {}

    impl Sealed for &str {
        fn to_header_name(&self) -> Option<Cow<'_, HeaderName>> {
            parse(self)
        }
    }

    impl AsHeaderName for &str {}

    impl Sealed for String {
        fn to_header_name(&self) -> Option<Cow<'_, HeaderName>> {
            parse(self)
        }
    }

    impl AsHeaderName for String {}

    impl Sealed for &String {
        fn to_header_name(&self) -> Option<Cow<'_, HeaderName>> {
            parse(self)
        }
    }

    impl AsHeaderName for &String {}
}

#[cfg(test)]
mod tests {
    use super::{
        super::{CALL_ID, CONTACT, TO, VIA},
        *,
    };

    fn value(src: &'static str) -> HeaderValue {
        HeaderValue::from_static(src)
    }

    fn rows(map: &HeaderMap) -> Vec<(&str, &str)> {
        map.iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    #[test]
    fn new_map_is_empty() {
        let map = HeaderMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert_eq!(map.capacity(), 0);
        assert!(map.get(VIA).is_none());
        assert_eq!(map.get_all(VIA).count(), 0);
    }

    #[test]
    fn append_keeps_wire_order_across_names() {
        let mut map = HeaderMap::new();
        assert!(!map.append(VIA, value("a")));
        assert!(!map.append(TO, value("b")));
        assert!(map.append(VIA, value("c")));

        assert_eq!(map.len(), 3);
        assert_eq!(rows(&map), [("Via", "a"), ("To", "b"), ("Via", "c")]);
        assert_eq!(map.get(VIA).unwrap(), "a");
        assert_eq!(map.get_all(VIA).collect::<Vec<_>>(), ["a", "c"]);
        assert_eq!(map.get_all(VIA).rev().collect::<Vec<_>>(), ["c", "a"]);
    }

    #[test]
    fn insert_replaces_in_place_and_drops_the_rest() {
        let mut map: HeaderMap = [
            (CONTACT, value("a")),
            (VIA, value("b")),
            (TO, value("c")),
            (VIA, value("d")),
        ]
        .into_iter()
        .collect();

        assert_eq!(map.insert(VIA, value("e")).unwrap(), "b");
        assert_eq!(rows(&map), [("Contact", "a"), ("Via", "e"), ("To", "c")]);

        assert!(map.insert(CALL_ID, value("f")).is_none());
        assert_eq!(rows(&map).last(), Some(&("Call-ID", "f")));
    }

    #[test]
    fn remove_drops_every_row_with_the_name() {
        let mut map: HeaderMap =
            [(VIA, value("a")), (TO, value("b")), (VIA, value("c"))]
                .into_iter()
                .collect();

        assert_eq!(map.remove("via").unwrap(), "a");
        assert_eq!(rows(&map), [("To", "b")]);
        assert!(map.remove(VIA).is_none());
    }

    #[test]
    fn lookups_accept_names_and_strings() {
        let mut map = HeaderMap::new();
        map.append(VIA, value("a"));
        map.append(HeaderName::from_static("x-custom"), value("b"));

        assert!(map.contains_key(VIA));
        assert!(map.contains_key(&VIA));
        assert!(map.contains_key("VIA"));
        assert!(map.contains_key("v"));
        let owned = String::from("Via");
        assert!(map.contains_key(&owned));
        assert!(map.contains_key(owned));
        assert_eq!(map.get("X-Custom").unwrap(), "b");
    }

    #[test]
    fn invalid_names_match_nothing() {
        let mut map = HeaderMap::new();
        map.append(VIA, value("a"));

        assert!(map.get("Via ").is_none());
        assert!(map.get("").is_none());
        assert_eq!(map.get_all("V:a").count(), 0);
        assert!(map.remove("bad name").is_none());
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn get_mut_changes_the_first_row() {
        let mut map: HeaderMap =
            [(VIA, value("a")), (VIA, value("b"))].into_iter().collect();

        *map.get_mut(VIA).unwrap() = value("c");
        assert_eq!(map.get_all(VIA).collect::<Vec<_>>(), ["c", "b"]);
    }

    #[test]
    fn extend_and_into_iter_keep_order() {
        let mut map = HeaderMap::with_capacity(4);
        assert!(map.capacity() >= 4);

        map.extend([(TO, value("a")), (VIA, value("b")), (TO, value("c"))]);
        let owned: Vec<_> = map
            .clone()
            .into_iter()
            .map(|(name, value)| (name.to_string(), value.as_str().to_owned()))
            .collect();
        assert_eq!(
            owned,
            [
                ("To".to_owned(), "a".to_owned()),
                ("Via".to_owned(), "b".to_owned()),
                ("To".to_owned(), "c".to_owned()),
            ]
        );

        map.clear();
        assert!(map.is_empty());
        assert!(map.capacity() >= 3);
    }

    #[test]
    fn debug_lists_rows_in_order() {
        let map: HeaderMap =
            [(VIA, value("a")), (TO, value("b"))].into_iter().collect();
        assert_eq!(format!("{map:?}"), r#"{Via: "a", To: "b"}"#);
    }
}
