/*!
The transports, on tokio.

[`udp::Socket`] carries datagrams and [`tcp`] carries streams. Each hands the
endpoint what arrived together with the [`Flow`] it arrived on, and takes
encoded bytes to send. The endpoint parses datagrams itself with
`Message::from_shared`. The TCP reader runs the stream decoder, because a
stream has to be framed before anything can be done with it.

Nothing here is public yet. The two transports are written to one shape so that
a trait can be extracted once a transport outside signa exists to validate it,
such as one on a raw socket that carries Ethernet-level data.
*/

use std::net::SocketAddr;

pub mod tcp;
pub mod udp;

/// The protocol a message travels over.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Transport {
    /// UDP. Unreliable, so transactions retransmit over it.
    Udp,
    /// TCP. Reliable.
    Tcp,
}

/// A transport-layer association, which RFC 5626 section 3 calls a flow: the
/// transport, and the address and port of both ends.
///
/// A flow says where a message came from and where its answer goes. Over UDP
/// the local address is the one the datagram was received on, which matters on
/// a socket bound to a wildcard address. Over TCP it is the connection's own.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Flow {
    /// The protocol.
    pub transport: Transport,
    /// This end.
    pub local: SocketAddr,
    /// The other end.
    pub remote: SocketAddr,
}
