//! Non-INVITE transaction state machines, sans-IO.

pub use self::{
    client::{ClientEvent, ClientTransaction},
    server::ServerTransaction,
};

mod client;
mod server;
