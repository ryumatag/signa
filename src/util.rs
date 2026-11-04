use std::{ops, str};

use bytes::Bytes;

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ByteStr {
    bytes: Bytes,
}

impl ByteStr {
    #[inline]
    pub(crate) const fn from_static(src: &'static str) -> ByteStr {
        ByteStr { bytes: Bytes::from_static(src.as_bytes()) }
    }

    /// # Safety
    ///
    /// `bytes` must be valid UTF-8.
    #[inline]
    pub(crate) unsafe fn from_utf8_unchecked(bytes: Bytes) -> ByteStr {
        if cfg!(debug_assertions) {
            match str::from_utf8(&bytes) {
                Ok(_) => (),
                Err(err) => panic!(
                    "ByteStr::from_utf8_unchecked() with invalid bytes; error = {}, bytes = {:?}",
                    err, bytes
                ),
            }
        }

        ByteStr { bytes }
    }
}

impl ops::Deref for ByteStr {
    type Target = str;

    #[inline]
    fn deref(&self) -> &str {
        let b: &[u8] = self.bytes.as_ref();
        // SAFETY: Every constructor takes a `str` or is `from_utf8_unchecked`,
        // whose caller guarantees valid UTF-8.
        unsafe { str::from_utf8_unchecked(b) }
    }
}

impl From<String> for ByteStr {
    #[inline]
    fn from(src: String) -> ByteStr {
        ByteStr { bytes: Bytes::from(src) }
    }
}

impl<'a> From<&'a str> for ByteStr {
    #[inline]
    fn from(src: &'a str) -> ByteStr {
        ByteStr { bytes: Bytes::copy_from_slice(src.as_bytes()) }
    }
}

impl From<ByteStr> for Bytes {
    fn from(src: ByteStr) -> Self {
        src.bytes
    }
}
