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

use std::{fmt, net::SocketAddr};

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

impl Transport {
    /// Returns `true` if the transport delivers what is sent, so that
    /// transactions need not retransmit over it (RFC 3261 section 17).
    pub fn is_reliable(self) -> bool {
        match self {
            Transport::Udp => false,
            Transport::Tcp => true,
        }
    }
}

impl fmt::Display for Transport {
    /// The name as it appears in a `Via` (RFC 3261 section 20.42).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
        })
    }
}

/// A transport-layer association, which RFC 5626 section 3 calls a flow: the
/// transport, and the address and port of both ends.
///
/// A flow says where a message came from and where its answer goes. Over UDP
/// the local address is the one the datagram was received on, which matters on
/// a socket bound to a wildcard address. Over TCP it is the connection's own.
///
/// The endpoint puts the flow a request arrived on into the request's
/// extensions, so a service can see where it came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Flow {
    /// The protocol.
    pub transport: Transport,
    /// This end.
    pub local: SocketAddr,
    /// The other end.
    pub remote: SocketAddr,
}
