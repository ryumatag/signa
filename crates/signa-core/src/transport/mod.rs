/*!
Transport metadata and message/write limits.

[`Flow`], [`Transport`], [`MessageLimits`] and [`WriteLimits`] are runtime
independent, and so is the [`datagram`] contract that lets another backend
carry an endpoint's UDP datagrams. Socket I/O and stream framing remain
implementation details used by the endpoint. TCP connections are framed by Content-Length before messages
reach the driver; UDP datagrams already carry their boundaries.
*/

use std::{fmt, net::SocketAddr};

#[cfg(feature = "tokio")]
pub(crate) mod budget;
pub mod datagram;

#[cfg(all(feature = "tokio", feature = "__bench"))]
#[doc(hidden)]
pub mod tcp;
#[cfg(all(feature = "tokio", not(feature = "__bench")))]
#[allow(unreachable_pub)]
pub(crate) mod tcp;
#[cfg(all(feature = "tokio", feature = "__bench"))]
#[doc(hidden)]
pub mod udp;
#[cfg(all(feature = "tokio", not(feature = "__bench")))]
#[allow(unreachable_pub)]
pub(crate) mod udp;

#[cfg(any(feature = "tokio", feature = "__bench", test))]
#[cfg_attr(not(feature = "__bench"), allow(unreachable_pub))]
pub(crate) mod framing;

/// Receive limits for one SIP message on a stream transport.
///
/// Both limits bound what one message can make the decoder hold. A head is
/// buffered whole before it is parsed, and a body is buffered whole before the
/// message is returned.
#[derive(Clone, Copy, Debug)]
pub struct MessageLimits {
    /// The most bytes a head may take, including its empty line.
    pub head: usize,
    /// The most bytes a body may take.
    pub body: usize,
}

impl Default for MessageLimits {
    /// Allows 64 KiB for a head and 1 MiB for a body.
    ///
    /// A head is rarely more than a few KiB even after a long chain of
    /// proxies, and hyper buffers at most about 400 KiB of HTTP/1 head. A body
    /// is usually a small SDP or text, but SIP holds it in memory whole, so it
    /// needs a limit too.
    fn default() -> MessageLimits {
        MessageLimits { head: 64 * 1024, body: 1024 * 1024 }
    }
}

/// Outstanding writes on one TCP connection or an endpoint's UDP socket.
///
/// Both limits include writes already taken from the queue but not yet fully
/// written to the local socket. Bytes count the complete encoded messages,
/// including headers. Capacity is returned at completion or teardown, even
/// when the caller drops its completion future. This does not cap shared
/// backing allocations or buffers owned by the operating system.
#[derive(Clone, Copy, Debug)]
pub struct WriteLimits {
    /// The most simultaneous writes. Zero refuses every write.
    pub messages: usize,
    /// The aggregate encoded bytes. Zero allows only empty writes.
    pub bytes: usize,
}

impl Default for WriteLimits {
    /// Allows 64 outstanding writes and 8 MiB per TCP connection.
    /// The endpoint uses 1024 writes and 8 MiB for its UDP socket by default.
    fn default() -> WriteLimits {
        WriteLimits { messages: 64, bytes: 8 * 1024 * 1024 }
    }
}

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
/// The endpoint delivers the flow a request arrived on in its incoming
/// envelope, as `ServerRequest::flow` and `ReceivedRequest::flow`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Flow {
    /// The protocol.
    pub transport: Transport,
    /// This end.
    pub local: SocketAddr,
    /// The other end.
    pub remote: SocketAddr,
}
