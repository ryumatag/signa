use std::{borrow::Cow, fmt, iter::FusedIterator};

/// One validated, possibly percent-escaped SIP URI component.
///
/// Getters preserve the wire text. Decoding is explicit and returns bytes,
/// including non-UTF-8 octets. This is URI escaping, so `+` is never a space.
#[derive(Clone, Copy)]
pub struct Component<'a>(pub(super) &'a str);

impl<'a> Component<'a> {
    /// Returns the original spelling, including escapes.
    pub fn as_str(self) -> &'a str {
        self.0
    }

    /// Iterates decoded octets without allocating.
    pub fn decoded_bytes(self) -> DecodedBytes<'a> {
        DecodedBytes(self.0.as_bytes())
    }

    /// Decodes percent escapes, borrowing when there are none.
    pub fn decode(self) -> Cow<'a, [u8]> {
        if self.0.as_bytes().contains(&b'%') {
            Cow::Owned(self.decoded_bytes().collect())
        } else {
            Cow::Borrowed(self.0.as_bytes())
        }
    }

    pub(super) fn name_is(self, name: &str) -> bool {
        self.decoded_bytes()
            .map(|b| b.to_ascii_lowercase())
            .eq(name.bytes().map(|b| b.to_ascii_lowercase()))
    }
}

impl AsRef<str> for Component<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl fmt::Debug for Component<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for Component<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Decoded octets of a validated URI component.
#[derive(Clone, Debug)]
pub struct DecodedBytes<'a>(&'a [u8]);

impl Iterator for DecodedBytes<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        let (&byte, rest) = self.0.split_first()?;
        if byte != b'%' {
            self.0 = rest;
            return Some(byte);
        }

        // Component construction validates every percent triplet. Decode once,
        // without interpreting the resulting byte as syntax or decoding it again.
        let high = hex(rest[0]).expect("validated percent triplet");
        let low = hex(rest[1]).expect("validated percent triplet");
        self.0 = &rest[2..];
        Some(high * 16 + low)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.0.len();
        (len / 3 + usize::from(len % 3 != 0), Some(len))
    }
}

impl FusedIterator for DecodedBytes<'_> {}

pub(super) fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding_keeps_octets_and_never_applies_form_or_recursive_decoding() {
        let component = Component("a+%20%252f%00%ff");

        assert_eq!(component.decode().as_ref(), b"a+ %2f\0\xff");
        assert_eq!(
            component.decoded_bytes().collect::<Vec<_>>(),
            b"a+ %2f\0\xff"
        );
        assert_eq!(component.as_str(), "a+%20%252f%00%ff");
        assert!(matches!(Component("alice+work").decode(), Cow::Borrowed(_)));
        assert!(Component("%54ransport").name_is("TRANSPORT"));
    }

    #[test]
    fn decoded_iterator_bounds_and_fusion_hold_at_every_step() {
        let mut bytes = Component("a%00b%ff").decoded_bytes();

        for remaining in (0..=4).rev() {
            let (low, high) = bytes.size_hint();
            assert!(low <= remaining && remaining <= high.unwrap());
            if remaining != 0 {
                assert!(bytes.next().is_some());
            }
        }

        assert_eq!(bytes.next(), None);
        assert_eq!(bytes.next(), None);
    }
}
