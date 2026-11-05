/*!
SIP header field names, values, and the map that holds them.
*/

pub use self::{
    map::{AsHeaderName, GetAll, HeaderMap, IntoIter, Iter},
    name::{konst::*, HeaderName},
    value::{HeaderValue, ValueLines},
};

mod map;
mod name;
mod value;

// The protocol layer's own parsers for the few headers it reads. Everything
// `pub` in them exists for the `__bench` feature, which re-exports it.
// Without the feature nothing reaches it, which `unreachable_pub` would
// otherwise flag.
// TODO: Drop `dead_code` once the transports and transactions use them.
#[cfg_attr(not(feature = "__bench"), allow(unreachable_pub, dead_code))]
pub(crate) mod cseq;
#[cfg_attr(not(feature = "__bench"), allow(unreachable_pub, dead_code))]
pub(crate) mod via;
