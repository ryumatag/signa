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

pub mod error;
mod extensions;
pub mod header;
mod message;
mod method;
mod parse;
mod reason;
pub mod request;
pub mod response;
mod status;
mod uri;
mod util;
mod version;

#[doc(inline)]
pub use self::{
    error::Error,
    extensions::Extensions,
    header::{HeaderMap, HeaderName, HeaderValue},
    message::Message,
    method::Method,
    reason::ReasonPhrase,
    request::Request,
    response::Response,
    status::StatusCode,
    uri::Uri,
    version::Version,
};
