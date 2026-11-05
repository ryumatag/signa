/*!
SIP request method types.

This module defines [`Method`], a value type for SIP request methods.

The six core methods (`INVITE`, `ACK`, `OPTIONS`, `BYE`, `CANCEL`, `REGISTER`)
are defined in [RFC 3261]. The following well-known extension methods are also
recognized as first-class constants:

| Method      | RFC        |
|-------------|------------|
| `PRACK`     | [RFC 3262] |
| `UPDATE`    | [RFC 3311] |
| `MESSAGE`   | [RFC 3428] |
| `REFER`     | [RFC 3515] |
| `PUBLISH`   | [RFC 3903] |
| `INFO`      | [RFC 6086] |
| `SUBSCRIBE` | [RFC 6665] |
| `NOTIFY`    | [RFC 6665] |

Any other valid SIP `token` ([RFC 3261, Section 25.1]) is accepted as an
extension method and preserves its original casing.

[RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
[RFC 3261, Section 25.1]: https://www.rfc-editor.org/rfc/rfc3261#section-25.1
[RFC 3262]: https://www.rfc-editor.org/rfc/rfc3262
[RFC 3311]: https://www.rfc-editor.org/rfc/rfc3311
[RFC 3428]: https://www.rfc-editor.org/rfc/rfc3428
[RFC 3515]: https://www.rfc-editor.org/rfc/rfc3515
[RFC 3903]: https://www.rfc-editor.org/rfc/rfc3903
[RFC 6086]: https://www.rfc-editor.org/rfc/rfc6086
[RFC 6665]: https://www.rfc-editor.org/rfc/rfc6665
*/

use std::{
    fmt,
    str::{self, FromStr},
};

use siparse::check;

use crate::error::InvalidMethod;

use self::{
    extension::{AllocatedExtension, InlineExtension},
    Known::*,
    Repr::*,
};

/// A SIP request method.
///
/// This type recognizes the core SIP methods defined by RFC 3261 and also
/// supports extension methods that satisfy the SIP `token` grammar.
///
/// SIP methods are treated as case-sensitive protocol values.
///
/// Standard methods are recognized only in their canonical uppercase form, and
/// extension methods preserve their original casing.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Method(Repr);

#[derive(Clone, PartialEq, Eq, Hash)]
enum Repr {
    Known(Known),
    ExtensionInline(InlineExtension),
    ExtensionAllocated(AllocatedExtension),
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum Known {
    // Core SIP methods defined by RFC 3261.
    Invite,
    Ack,
    Options,
    Bye,
    Cancel,
    Register,

    // Well-known extension methods with dedicated constants.
    Prack,
    Subscribe,
    Notify,
    Publish,
    Info,
    Refer,
    Message,
    Update,
}

impl Method {
    /// The `INVITE` method.
    pub const INVITE: Method = Method(Known(Invite));

    /// The `ACK` method.
    pub const ACK: Method = Method(Known(Ack));

    /// The `OPTIONS` method.
    pub const OPTIONS: Method = Method(Known(Options));

    /// The `BYE` method.
    pub const BYE: Method = Method(Known(Bye));

    /// The `CANCEL` method.
    pub const CANCEL: Method = Method(Known(Cancel));

    /// The `REGISTER` method.
    pub const REGISTER: Method = Method(Known(Register));

    /// The `PRACK` method ([RFC 3262]).
    ///
    /// [RFC 3262]: https://www.rfc-editor.org/rfc/rfc3262
    pub const PRACK: Method = Method(Known(Prack));

    /// The `SUBSCRIBE` method ([RFC 6665]).
    ///
    /// [RFC 6665]: https://www.rfc-editor.org/rfc/rfc6665
    pub const SUBSCRIBE: Method = Method(Known(Subscribe));

    /// The `NOTIFY` method ([RFC 6665]).
    ///
    /// [RFC 6665]: https://www.rfc-editor.org/rfc/rfc6665
    pub const NOTIFY: Method = Method(Known(Notify));

    /// The `PUBLISH` method ([RFC 3903]).
    ///
    /// [RFC 3903]: https://www.rfc-editor.org/rfc/rfc3903
    pub const PUBLISH: Method = Method(Known(Publish));

    /// The `INFO` method ([RFC 6086]).
    ///
    /// [RFC 6086]: https://www.rfc-editor.org/rfc/rfc6086
    pub const INFO: Method = Method(Known(Info));

    /// The `REFER` method ([RFC 3515]).
    ///
    /// [RFC 3515]: https://www.rfc-editor.org/rfc/rfc3515
    pub const REFER: Method = Method(Known(Refer));

    /// The `MESSAGE` method ([RFC 3428]).
    ///
    /// [RFC 3428]: https://www.rfc-editor.org/rfc/rfc3428
    pub const MESSAGE: Method = Method(Known(Message));

    /// The `UPDATE` method ([RFC 3311]).
    ///
    /// [RFC 3311]: https://www.rfc-editor.org/rfc/rfc3311
    pub const UPDATE: Method = Method(Known(Update));

    /// Converts a byte slice to a `Method`.
    ///
    /// Known methods are recognized only in their canonical uppercase form.
    /// Any other valid SIP `token` is preserved as an extension method.
    pub fn from_bytes(src: &[u8]) -> Result<Method, InvalidMethod> {
        match src.len() {
            0 => Err(InvalidMethod::new()),
            3 => match src {
                b"ACK" => Ok(Method::ACK),
                b"BYE" => Ok(Method::BYE),
                _ => Method::extension_inline(src),
            },
            4 => match src {
                b"INFO" => Ok(Method::INFO),
                _ => Method::extension_inline(src),
            },
            5 => match src {
                b"PRACK" => Ok(Method::PRACK),
                b"REFER" => Ok(Method::REFER),
                _ => Method::extension_inline(src),
            },
            6 => match src {
                b"INVITE" => Ok(Method::INVITE),
                b"CANCEL" => Ok(Method::CANCEL),
                b"NOTIFY" => Ok(Method::NOTIFY),
                b"UPDATE" => Ok(Method::UPDATE),
                _ => Method::extension_inline(src),
            },
            7 => match src {
                b"OPTIONS" => Ok(Method::OPTIONS),
                b"MESSAGE" => Ok(Method::MESSAGE),
                b"PUBLISH" => Ok(Method::PUBLISH),
                _ => Method::extension_inline(src),
            },
            8 => match src {
                b"REGISTER" => Ok(Method::REGISTER),
                _ => Method::extension_inline(src),
            },
            9 => match src {
                b"SUBSCRIBE" => Ok(Method::SUBSCRIBE),
                _ => Method::extension_inline(src),
            },
            _ => {
                if src.len() <= InlineExtension::MAX {
                    Method::extension_inline(src)
                } else {
                    let allocated = AllocatedExtension::new(src)?;

                    Ok(Method(ExtensionAllocated(allocated)))
                }
            }
        }
    }

    /// Returns the canonical SIP method as a string slice.
    ///
    /// For extension methods, this returns the preserved token text.
    pub fn as_str(&self) -> &str {
        match self.0 {
            Known(ref known) => known.as_str(),
            ExtensionInline(ref ext) => ext.as_str(),
            ExtensionAllocated(ref ext) => ext.as_str(),
        }
    }

    fn extension_inline(src: &[u8]) -> Result<Method, InvalidMethod> {
        let inline = InlineExtension::new(src)?;
        Ok(Method(ExtensionInline(inline)))
    }
}

impl fmt::Debug for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl PartialEq<&Method> for Method {
    fn eq(&self, other: &&Method) -> bool {
        self == *other
    }
}

impl PartialEq<Method> for &Method {
    fn eq(&self, other: &Method) -> bool {
        *self == other
    }
}

impl PartialEq<str> for Method {
    fn eq(&self, other: &str) -> bool {
        self.as_ref() == other
    }
}

impl PartialEq<Method> for str {
    fn eq(&self, other: &Method) -> bool {
        self == other.as_ref()
    }
}

impl PartialEq<&str> for Method {
    fn eq(&self, other: &&str) -> bool {
        self.as_ref() == *other
    }
}

impl PartialEq<Method> for &str {
    fn eq(&self, other: &Method) -> bool {
        *self == other.as_ref()
    }
}

impl AsRef<str> for Method {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&Method> for Method {
    fn from(method: &Method) -> Self {
        method.clone()
    }
}

impl TryFrom<&[u8]> for Method {
    type Error = InvalidMethod;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        Method::from_bytes(src)
    }
}

impl TryFrom<&str> for Method {
    type Error = InvalidMethod;

    fn try_from(src: &str) -> Result<Self, Self::Error> {
        TryFrom::try_from(src.as_bytes())
    }
}

impl FromStr for Method {
    type Err = InvalidMethod;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        TryFrom::try_from(src)
    }
}

impl Known {
    fn as_str(&self) -> &str {
        match self {
            Invite => "INVITE",
            Ack => "ACK",
            Options => "OPTIONS",
            Bye => "BYE",
            Cancel => "CANCEL",
            Register => "REGISTER",
            Prack => "PRACK",
            Subscribe => "SUBSCRIBE",
            Notify => "NOTIFY",
            Publish => "PUBLISH",
            Info => "INFO",
            Refer => "REFER",
            Message => "MESSAGE",
            Update => "UPDATE",
        }
    }
}

mod extension {
    use super::*;

    #[derive(Clone, Eq, Hash, PartialEq)]
    // Invariant: the first self.1 bytes of self.0 are valid SIP token bytes.
    pub(super) struct InlineExtension([u8; InlineExtension::MAX], u8);

    #[derive(Clone, Eq, Hash, PartialEq)]
    // Invariant: self.0 contains valid SIP token bytes.
    pub(super) struct AllocatedExtension(Box<[u8]>);

    impl InlineExtension {
        // Inline storage is used for short extension methods to avoid
        // allocation in the common case.
        pub(super) const MAX: usize = 15;

        pub(super) fn new(
            src: &[u8],
        ) -> Result<InlineExtension, InvalidMethod> {
            let mut data = [0; InlineExtension::MAX];

            write_checked(src, &mut data)?;

            Ok(InlineExtension(data, src.len() as u8))
        }

        pub(super) fn as_str(&self) -> &str {
            let InlineExtension(data, len) = self;

            // SAFETY: SIP token bytes are ASCII and therefore valid UTF-8.
            unsafe { str::from_utf8_unchecked(&data[..*len as usize]) }
        }
    }

    impl AllocatedExtension {
        pub(super) fn new(
            src: &[u8],
        ) -> Result<AllocatedExtension, InvalidMethod> {
            let mut data = vec![0; src.len()];

            write_checked(src, &mut data)?;

            Ok(AllocatedExtension(data.into_boxed_slice()))
        }

        pub(super) fn as_str(&self) -> &str {
            // SAFETY: SIP token bytes are ASCII and therefore valid UTF-8.
            unsafe { str::from_utf8_unchecked(&self.0) }
        }
    }

    /// Copies `src` into `dst` if it is a SIP `token`.
    ///
    /// The check is siparse's, so an extension method is valid here exactly
    /// when the parser accepts it in a request-line.
    fn write_checked(src: &[u8], dst: &mut [u8]) -> Result<(), InvalidMethod> {
        let token = check::method(src).map_err(|_| InvalidMethod::new())?;
        dst[..token.len()].copy_from_slice(token.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_method_constants() {
        let cases = [
            ("INVITE", Method::INVITE),
            ("ACK", Method::ACK),
            ("OPTIONS", Method::OPTIONS),
            ("BYE", Method::BYE),
            ("CANCEL", Method::CANCEL),
            ("REGISTER", Method::REGISTER),
            ("PRACK", Method::PRACK),
            ("SUBSCRIBE", Method::SUBSCRIBE),
            ("NOTIFY", Method::NOTIFY),
            ("PUBLISH", Method::PUBLISH),
            ("INFO", Method::INFO),
            ("REFER", Method::REFER),
            ("MESSAGE", Method::MESSAGE),
            ("UPDATE", Method::UPDATE),
        ];

        for (src, konst) in cases {
            let parsed = Method::from_bytes(src.as_bytes()).unwrap();
            assert_eq!(parsed, konst);
            assert_eq!(parsed.as_str(), src);
            assert_eq!(parsed.to_string(), src);
            assert_eq!(format!("{parsed:?}"), src);
        }
    }

    #[test]
    fn non_canonical_case_becomes_extension() {
        let m = Method::from_bytes(b"invite").unwrap();
        assert_eq!(m.as_str(), "invite");
        assert_ne!(m, Method::INVITE);
    }

    #[test]
    fn rejects_invalid_inputs() {
        assert!(Method::from_bytes(b"").is_err());
        assert!(Method::from_bytes(b"IN VITE").is_err());
        assert!(Method::from_bytes(b"INVITE\r").is_err());
        assert!(Method::from_bytes(b"INVITE/").is_err());
        assert!(Method::from_bytes(&[0xff]).is_err());
    }

    #[test]
    fn inline_and_allocated_extension() {
        let inline_bytes = b"X-TEST";
        let inline = Method::from_bytes(inline_bytes).unwrap();
        assert_eq!(
            inline,
            Method(ExtensionInline(
                InlineExtension::new(inline_bytes).unwrap()
            ))
        );
        assert_eq!(inline.as_str(), str::from_utf8(inline_bytes).unwrap());

        let longest_inline_bytes = &[b'X'; InlineExtension::MAX];
        assert_eq!(
            Method::from_bytes(longest_inline_bytes).unwrap(),
            Method(Repr::ExtensionInline(
                InlineExtension::new(longest_inline_bytes).unwrap()
            ))
        );

        let allocated_bytes = b"THIS-IS-A-LONG-EXT";
        let allocated = Method::from_bytes(allocated_bytes).unwrap();
        assert_eq!(
            allocated,
            Method(ExtensionAllocated(
                AllocatedExtension::new(allocated_bytes).unwrap()
            ))
        );
        assert_eq!(
            allocated.as_str(),
            str::from_utf8(allocated_bytes).unwrap()
        );

        let shortest_allocated_bytes = &[b'X'; InlineExtension::MAX + 1];
        assert_eq!(
            Method::from_bytes(shortest_allocated_bytes).unwrap(),
            Method(Repr::ExtensionAllocated(
                AllocatedExtension::new(shortest_allocated_bytes).unwrap()
            ))
        );
    }

    #[test]
    fn parsing_apis_are_consistent() {
        let a = Method::from_bytes(b"INVITE").unwrap();
        let b = Method::try_from("INVITE").unwrap();
        let c = Method::from_str("INVITE").unwrap();

        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn invalid_method_error_text() {
        let err = Method::from_bytes(b"INV ITE").unwrap_err();
        assert_eq!(err.to_string(), "invalid SIP method");
        assert_eq!(format!("{err:?}"), "InvalidMethod");
    }
}
