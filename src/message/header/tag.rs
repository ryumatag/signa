use std::{fmt, str::FromStr};

use crate::message::error::InvalidTag;

/// The value of a `tag` parameter in `From` or `To`.
///
/// A tag is a SIP `token` ([RFC 3261 section 25.1]). Together with the
/// Call-ID, the two tags identify a dialog. [RFC 3261 section 19.3] requires
/// each tag that an element creates to be globally unique and to carry at least
/// 32 bits of cryptographic randomness. [`Tag::random`] meets that. A tag
/// parsed from a string is only checked for its syntax.
///
/// # Example
///
/// ```
/// use signa::message::header::Tag;
///
/// let fixed: Tag = "a6c85cf".parse()?;
/// assert_eq!(fixed.as_str(), "a6c85cf");
///
/// let fresh = Tag::random();
/// assert_ne!(fresh, Tag::random());
/// # Ok::<(), signa::message::error::InvalidTag>(())
/// ```
///
/// [RFC 3261 section 19.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-19.3
/// [RFC 3261 section 25.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-25.1
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Tag(Box<str>);

impl Tag {
    /// Creates a tag from 64 bits of operating system randomness, written as
    /// 16 lowercase hexadecimal digits.
    ///
    /// Each call reads the operating system's random source once.
    ///
    /// # Panics
    ///
    /// Panics if the operating system's random source fails. The supported
    /// platforms do not report such failures in normal operation.
    pub fn random() -> Tag {
        Tag::try_random().expect("the operating system provides randomness")
    }

    /// Returns `None` when the operating system's random source fails, for
    /// callers that must not panic, such as the endpoint driver.
    pub(crate) fn try_random() -> Option<Tag> {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes).ok()?;

        Some(Tag(format!("{:016x}", u64::from_ne_bytes(bytes)).into()))
    }

    /// Returns the tag as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Tag {
    type Err = InvalidTag;

    fn from_str(src: &str) -> Result<Tag, InvalidTag> {
        match siparse::scan::token(src) {
            Some((_, "")) => Ok(Tag(src.into())),
            _ => Err(InvalidTag::new()),
        }
    }
}

impl TryFrom<&str> for Tag {
    type Error = InvalidTag;

    fn try_from(src: &str) -> Result<Tag, InvalidTag> {
        src.parse()
    }
}

impl TryFrom<String> for Tag {
    type Error = InvalidTag;

    fn try_from(src: String) -> Result<Tag, InvalidTag> {
        match siparse::scan::token(&src) {
            Some((_, "")) => Ok(Tag(src.into_boxed_str())),
            _ => Err(InvalidTag::new()),
        }
    }
}

impl AsRef<str> for Tag {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_tokens() {
        for valid in ["1928301774", "a6c85cf", "x.y-z_!%*+`'~"] {
            assert_eq!(valid.parse::<Tag>().unwrap().as_str(), valid);
        }

        for invalid in ["", "has space", "semi;colon", "quote\"", "tag=x"] {
            assert!(invalid.parse::<Tag>().is_err(), "{invalid}");
            assert!(Tag::try_from(invalid.to_owned()).is_err(), "{invalid}");
        }
    }

    #[test]
    fn random_tags_have_64_bits_in_hex() {
        let tag = Tag::random();

        assert_eq!(tag.as_str().len(), 16);
        assert!(tag.as_str().bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(tag.as_str().parse::<Tag>().unwrap(), tag);
    }
}
