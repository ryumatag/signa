/*!
SIP header field names and values.
*/

mod name;
mod value;

pub use self::{
    name::{konst::*, HeaderName, InvalidHeaderName},
    value::{HeaderValue, InvalidHeaderValue, ValueLines},
};
