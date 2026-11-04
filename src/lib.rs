/*!
WORK IN PROGRESS.
*/

#![allow(
    // My preference.
    clippy::use_self,
    clippy::needless_lifetimes,
)]
#![deny(
    unreachable_pub,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks,
    rustdoc::broken_intra_doc_links
)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod header;
mod method;
mod status;
mod util;
mod version;

#[doc(inline)]
pub use self::{
    header::{HeaderName, HeaderValue, InvalidHeaderName, InvalidHeaderValue},
    method::{InvalidMethod, Method},
    status::{InvalidStatusCode, StatusCode},
    version::Version,
};
