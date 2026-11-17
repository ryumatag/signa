/*!
Transport metadata and message/write limits.

[`Flow`], [`Transport`], [`ReceiveId`], [`MessageLimits`] and [`Limits`]
are runtime independent, and so is the [`datagram`] contract that lets
another backend carry an endpoint's UDP datagrams. Socket I/O and stream framing remain
implementation details used by the endpoint. TCP connections are framed by Content-Length before messages
reach the driver; UDP datagrams already carry their boundaries.
*/

use std::{
    fmt,
    net::{SocketAddr, SocketAddrV4},
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

// Without tokio nothing takes a permit, but a kept path still names its type.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
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

/// How many items something may hold at once, and how many bytes they may
/// take together.
///
/// The setting that takes it says what an item is: an outstanding write, a
/// queued response or event, a copied transport context, a held datagram or
/// an observation record. Outstanding writes include those already taken
/// from the queue but not yet fully written, and their bytes are the complete
/// encoded messages, headers included. Capacity comes back when an item is
/// done with, such as at a write's completion or teardown, even when the
/// caller drops its future. This does not cap shared backing allocations or
/// buffers owned by the operating system.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// The most items at once. Zero refuses every item.
    pub count: usize,
    /// The most bytes the items take together. Zero allows only empty items.
    pub bytes: usize,
}

impl Default for Limits {
    /// Allows 64 items and 8 MiB, the outstanding writes of one TCP
    /// connection. Each setting that takes limits states its own default.
    fn default() -> Limits {
        Limits { count: 64, bytes: 8 * 1024 * 1024 }
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

/// A transport-layer association, which [RFC 5626 section 2.1] calls a flow:
/// the transport, and the address and port of both ends.
///
/// A flow says where a message came from and where its answer goes. Over UDP
/// the local address is the one the datagram was received on, which matters on
/// a socket bound to a wildcard address. Over TCP it is the connection's own.
///
/// The endpoint delivers the flow a message arrived on in its incoming
/// envelope, as the `ReceiveInfo::flow` of its `received` field.
///
/// [RFC 5626 section 2.1]: https://www.rfc-editor.org/rfc/rfc5626.html#section-2.1
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Flow {
    /// The protocol.
    pub transport: Transport,
    /// This end.
    pub local: SocketAddr,
    /// The other end.
    pub remote: SocketAddr,
}

/// Names one received message within the process.
///
/// The endpoint numbers each message where it first arrives: a datagram as
/// the endpoint's backend or a shared port's task takes it, and a TCP message
/// as its connection frames it. The ID stays the same however far the message
/// travels, through an application's decision on a shared port included.
///
/// The [`domain`](ReceiveId::domain) names where it arrived: an endpoint's
/// own UDP backend, a shared port or one TCP connection. No two of them in a
/// process get the same domain, and none is reused. The
/// [`sequence`](ReceiveId::sequence) counts the messages of that domain from
/// zero, in the order they arrived. Two datagrams with the same bytes, such as
/// a retransmission, get two IDs.
///
/// It is a name, not a capability. Nothing sends with it.
///
/// IDs order by domain, then by sequence. Only the order within one domain
/// means anything: it is the order the messages arrived in. Domains are
/// numbered as they are made, so the order of two IDs of different domains
/// says nothing about which message came first.
///
/// It displays as the domain and the sequence, as in `7:42`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReceiveId {
    domain: u64,
    sequence: u64,
}

impl ReceiveId {
    /// The backend, port or connection the message arrived on.
    pub fn domain(&self) -> u64 {
        self.domain
    }

    /// The message's place among those of its domain, from zero.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl fmt::Display for ReceiveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.domain, self.sequence)
    }
}

/// A received message's ID and the time it arrived, made once where it
/// arrived and carried unchanged from there.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) struct Stamp {
    pub(crate) id: ReceiveId,
    pub(crate) at: Instant,
}

/// Stamps the messages of one receive point, which one task owns.
///
/// The sequence is a plain counter, since only that task stamps. It cannot
/// wrap in practice. At a billion messages a second that would take 584
/// years.
#[derive(Debug)]
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) struct Stamps {
    domain: u64,
    next: u64,
}

#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
impl Stamps {
    /// Stamps for a new domain.
    pub(crate) fn new() -> Stamps {
        Stamps::in_domain(next_id())
    }

    /// Stamps for `domain`, a number from [`next_id`] that names something
    /// else too, such as an endpoint's binding.
    pub(crate) fn in_domain(domain: u64) -> Stamps {
        Stamps { domain, next: 0 }
    }

    /// Stamps the next message, which arrived `at`.
    pub(crate) fn stamp(&mut self, at: Instant) -> Stamp {
        let sequence = self.next;
        self.next = self.next.wrapping_add(1);
        Stamp { id: ReceiveId { domain: self.domain, sequence }, at }
    }
}

/// A number that nothing else in this process gets: for a port, an endpoint
/// registration or a receive domain.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) fn next_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// `addr` with an IPv4-mapped IPv6 address in its IPv4 form, and any other
/// address as it is.
///
/// A dual-stack socket names an IPv4 peer by its mapped form, but a `Via`
/// names it by its IPv4 address, and so do `received` and the transaction
/// keys. A native IPv6 address keeps its scope ID and flow label. A reply to
/// a link-local peer needs the scope to leave on the interface the request
/// came in on.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::V4(SocketAddrV4::new(ip, v6.port())),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

    use super::*;

    // A receive ID reads as its domain and sequence, which is what a log
    // needs to find the message in an observer's records.
    #[test]
    fn a_receive_id_displays_its_domain_and_sequence() {
        let id = Stamps::in_domain(7).stamp(Instant::now()).id;

        assert_eq!(id.to_string(), "7:0");
    }

    #[test]
    fn unmap_turns_a_mapped_address_back() {
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped(),
            5060,
            0,
            0,
        ));
        let plain = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(192, 0, 2, 1),
            5060,
        ));

        assert_eq!(unmap(mapped), plain);
        assert_eq!(unmap(plain), plain);

        // An IPv4 address has neither a scope nor a flow label to keep.
        let labelled = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped(),
            5060,
            0x12345,
            7,
        ));
        assert_eq!(unmap(labelled), plain);
    }

    #[test]
    fn unmap_keeps_a_native_ipv6_address_whole() {
        let link_local = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x20),
            5070,
            0x12345,
            7,
        ));
        let loopback =
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5060, 0, 0));

        assert_eq!(unmap(link_local), link_local);
        assert_eq!(unmap(loopback), loopback);
    }
}
