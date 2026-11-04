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

mod extensions;
pub mod header;
mod method;
mod reason;
mod status;
mod uri;
mod util;
mod version;

#[doc(inline)]
pub use self::{
    extensions::Extensions,
    header::{
        HeaderMap, HeaderName, HeaderValue, InvalidHeaderName,
        InvalidHeaderValue,
    },
    method::{InvalidMethod, Method},
    reason::{InvalidReasonPhrase, ReasonPhrase},
    status::{InvalidStatusCode, StatusCode},
    uri::{InvalidUri, Uri},
    version::Version,
};
