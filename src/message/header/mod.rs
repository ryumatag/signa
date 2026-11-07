/*!
SIP header field names, values, and the map that holds them.
*/

pub use self::{
    map::{AsHeaderName, GetAll, HeaderMap, IntoIter, Iter},
    name::{konst::*, HeaderName},
    tag::Tag,
    value::{HeaderValue, ValueLines},
};

mod map;
mod name;
mod tag;
mod value;

// Only the protocol layers interpret these headers. The message model
// otherwise keeps values opaque, except that the response builder checks for an
// existing To tag. Their lexical helpers are shared with tests and benchmarks
// without making typed header parsing a public API.
pub(crate) mod address;
#[cfg(any(feature = "tokio", feature = "__bench", test))]
#[cfg_attr(not(feature = "__bench"), allow(unreachable_pub))]
pub(crate) mod cseq;
#[cfg(any(feature = "tokio", feature = "__bench", test))]
#[cfg_attr(not(feature = "__bench"), allow(unreachable_pub))]
pub(crate) mod via;
