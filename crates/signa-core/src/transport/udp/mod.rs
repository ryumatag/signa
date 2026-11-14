/*!
The UDP transport.

One socket sends and receives. [`Socket::recv`] returns each datagram as
`Bytes` cut from a read buffer the datagrams share, with the flow it arrived
on. [`Socket::send`] sends one datagram to the remote address of a flow from
its local address.

On Linux, Android, and Apple platforms the socket asks the kernel for the
destination address of each datagram (`IP_PKTINFO`, `IPV6_RECVPKTINFO`) and
names the source address of each datagram it sends. A socket bound to a
wildcard address therefore knows which address a request came to and answers
from that address. A peer behind a NAT needs that, because its NAT only passes
a response from the address the request went to. Elsewhere the local address of
a flow is the socket's own, which is the wildcard when it is bound to one, and
the kernel picks the source.

The datagrams signa sends are small enough to fragment rather than to refuse.
Nothing here sets the don't-fragment bit, and a datagram above the MTU goes out
in pieces, as RFC 3261 section 18.1.1 allows for the replies that have no other
way back.

[`Io`] is the socket as the endpoint's [`DatagramIo`] backend.
*/

use std::{
    collections::VecDeque,
    future::poll_fn,
    io,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    task::{Context, Poll, ready},
};

use bytes::{Bytes, BytesMut};
use tokio::{io::Interest, net::UdpSocket};

use super::{
    Flow, Transport,
    datagram::{
        Capabilities, Datagram, DatagramIo, DatagramWrite, RecvError, Submit,
        TransportContext, WriteId,
    },
};

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple"
))]
#[path = "pktinfo.rs"]
mod sys;
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple"
)))]
#[path = "plain.rs"]
mod sys;

/// The most bytes a datagram can carry. An IPv4 datagram holds at most 65507
/// bytes of UDP payload, so this is room enough for any of them.
const MAX_DATAGRAM: usize = u16::MAX as usize;

/// How much the read buffer grows at a time. Every receive needs room for the
/// largest datagram, so a chunk must be larger than that for datagrams to
/// share one. 256 KiB takes a few hundred typical datagrams per allocation,
/// and a retained message holds at most that much with it.
const CHUNK: usize = 4 * MAX_DATAGRAM;

/// One datagram, as the platform layer reports it.
struct Received {
    /// Its length. The platform layer has already advanced the buffer.
    len: usize,
    /// Where it came from.
    remote: SocketAddr,
    /// The address it was sent to, when the platform reports it.
    local: Option<IpAddr>,
}

/// A UDP socket that sends and receives SIP datagrams.
#[derive(Debug)]
pub struct Socket {
    inner: UdpSocket,
    local: SocketAddr,
}

impl Socket {
    /// Binds a socket to `addr`.
    ///
    /// Must be called from within a tokio runtime, since the socket registers
    /// with its reactor.
    pub fn bind(addr: SocketAddr) -> io::Result<Socket> {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;

        let local = socket.local_addr()?;
        sys::configure(&socket, local.is_ipv4())?;

        let inner = UdpSocket::from_std(socket)?;

        Ok(Socket { inner, local })
    }

    /// The address the socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Receives one datagram and returns it with the flow it arrived on.
    ///
    /// `buf` is scratch for the socket. The call clears it, reads into it, and
    /// cuts the datagram off, so consecutive datagrams share one allocation of
    /// [`CHUNK`] bytes until it is used up. Each returned `Bytes` keeps its
    /// chunk alive, so a message that lives long holds the other datagrams
    /// read into the same chunk with it. Pass the same buffer to every call to
    /// get that sharing.
    ///
    /// The endpoint polls with [`Socket::poll_recv`] from its own loop. This
    /// waits, for the tests and the benchmarks.
    #[cfg_attr(not(any(test, feature = "__bench")), allow(dead_code))]
    pub async fn recv(&self, buf: &mut BytesMut) -> io::Result<(Bytes, Flow)> {
        poll_fn(|cx| self.poll_recv(cx, buf)).await
    }

    /// Polls for one datagram. See [`Socket::recv`].
    pub fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut BytesMut,
    ) -> Poll<io::Result<(Bytes, Flow)>> {
        buf.clear();
        // A chunk at a time, not a datagram at a time. `reserve` reuses the
        // allocation when no datagram from it is alive any more.
        if buf.capacity() < MAX_DATAGRAM {
            buf.reserve(CHUNK);
        }
        let received = loop {
            ready!(self.inner.poll_recv_ready(cx))?;
            // `try_io` clears the readiness on `WouldBlock`, so the next
            // round waits for the reactor again.
            match self
                .inner
                .try_io(Interest::READABLE, || sys::recv(&self.inner, buf))
            {
                Ok(received) => break received,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Poll::Ready(Err(err)),
            }
        };
        let datagram = buf.split_to(received.len).freeze();

        // A dual-stack socket reports IPv4 peers as mapped IPv6 addresses.
        // The `Via` of such a peer names the IPv4 address, so `received` and
        // the key comparisons want it in that form.
        let remote = unmap(received.remote);
        let local = match received.local {
            Some(ip) => unmap(SocketAddr::new(ip, self.local.port())),
            None => self.local,
        };
        let flow = Flow { transport: Transport::Udp, local, remote };

        Poll::Ready(Ok((datagram, flow)))
    }

    /// Sends `data` to the remote address of `flow`, from its local address
    /// where the platform lets the socket choose one.
    ///
    /// The local address only matters on a socket bound to a wildcard address.
    /// A socket bound to one address always sends from it.
    ///
    /// The endpoint uses [`Socket::try_send`], since it must not wait on one
    /// flow. This waits, for the tests and the benchmarks.
    #[cfg_attr(not(any(test, feature = "__bench")), allow(dead_code))]
    pub async fn send(&self, data: &[u8], flow: &Flow) -> io::Result<()> {
        let (remote, source) = self.addresses(flow);
        let sent = self
            .inner
            .async_io(Interest::WRITABLE, || {
                sys::send(&self.inner, data, remote, source)
            })
            .await?;
        // A datagram goes out whole or not at all, so a short count cannot
        // happen. This guards the platform layer, not the kernel.
        debug_assert_eq!(sent, data.len());

        Ok(())
    }

    /// Polls for the socket to be writable, which [`Socket::try_send`] needs
    /// before it can send anything.
    pub fn poll_send_ready(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.poll_send_ready(cx)
    }

    /// Sends `data` as [`Socket::send`] does, without waiting.
    ///
    /// # Errors
    ///
    /// Fails with [`io::ErrorKind::WouldBlock`] when the socket's send buffer
    /// is full, or when the reactor has not yet seen the socket writable,
    /// which is so until [`Socket::poll_send_ready`] has been polled once. The
    /// endpoint queues the datagram and sends it when the socket is writable,
    /// rather than wait on one flow.
    pub fn try_send(&self, data: &[u8], flow: &Flow) -> io::Result<()> {
        let (remote, source) = self.addresses(flow);
        let sent = self.inner.try_io(Interest::WRITABLE, || {
            sys::send(&self.inner, data, remote, source)
        })?;
        debug_assert_eq!(sent, data.len());

        Ok(())
    }

    /// The destination and the source to give the platform layer for a send on
    /// `flow`.
    fn addresses(&self, flow: &Flow) -> (SocketAddr, Option<IpAddr>) {
        // A socket bound to IPv6 reaches IPv4 peers through mapped addresses.
        // The other way around cannot work, and the kernel reports it.
        let remote = match (self.local, flow.remote) {
            (SocketAddr::V6(_), SocketAddr::V4(remote)) => {
                let ip = remote.ip().to_ipv6_mapped();
                SocketAddr::V6(SocketAddrV6::new(ip, remote.port(), 0, 0))
            }
            (_, remote) => remote,
        };
        let source = match (self.local.ip(), flow.local.ip()) {
            (bound, source) if bound.is_unspecified() => {
                let source = match (self.local, source) {
                    (SocketAddr::V6(_), IpAddr::V4(ip)) => {
                        IpAddr::V6(ip.to_ipv6_mapped())
                    }
                    (_, ip) => ip,
                };
                (!source.is_unspecified()).then_some(source)
            }
            _ => None,
        };

        (remote, source)
    }
}

/// The socket as a [`DatagramIo`] backend.
///
/// A send happens in [`DatagramIo::poll_submit`]. One the kernel takes is
/// accepted and complete, and one it refuses is rejected with its error, so
/// [`DatagramIo::poll_complete`] only hands back what the last submissions
/// accepted. Nothing is ever outstanding when the endpoint closes it.
#[derive(Debug)]
pub struct Io {
    socket: Socket,
    buf: BytesMut,
    done: VecDeque<WriteId>,
}

impl Io {
    /// Wraps a bound socket.
    pub fn new(socket: Socket) -> Io {
        Io { socket, buf: BytesMut::new(), done: VecDeque::new() }
    }
}

impl DatagramIo for Io {
    fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr()
    }

    /// The largest UDP payload of the socket's address family: 65507 bytes
    /// over IPv4 and 65527 over IPv6 without jumbograms.
    fn capabilities(&self) -> Capabilities {
        Capabilities::new(match self.socket.local_addr() {
            SocketAddr::V4(_) => 65_507,
            SocketAddr::V6(_) => 65_527,
        })
    }

    // The read buffer always has room for `MAX_DATAGRAM` bytes, more than any
    // UDP payload, so a datagram is never truncated.
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Datagram, RecvError>> {
        let (payload, flow) =
            ready!(self.socket.poll_recv(cx, &mut self.buf))?;
        Poll::Ready(Ok(Datagram::new(payload, flow.remote, flow.local)))
    }

    fn poll_submit(
        &mut self,
        cx: &mut Context<'_>,
        write: DatagramWrite,
    ) -> Submit {
        let flow = Flow {
            transport: Transport::Udp,
            local: write.source(),
            remote: write.destination(),
        };
        // `try_send` fails at once until the reactor has seen the socket
        // writable, and a send can race readiness being cleared. A second
        // round settles both. A third would only spin.
        for _ in 0..2 {
            match self.socket.try_send(write.payload(), &flow) {
                Ok(()) => {
                    self.done.push_back(write.id());
                    return Submit::Accepted;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Submit::Rejected(write, error),
            }
            match self.socket.poll_send_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => {
                    return Submit::Rejected(write, error);
                }
                Poll::Pending => return Submit::Pending(write),
            }
        }

        cx.waker().wake_by_ref();
        Submit::Pending(write)
    }

    /// Accepts a unicast source on the socket's port, at its own IP address,
    /// or at any address when the socket is bound to a wildcard and names the
    /// source of each datagram it sends. The check cannot prove that such an
    /// address belongs to this host. That shows when the kernel refuses a
    /// write from it. Where the socket cannot name a source, only its own
    /// address is accepted, since the kernel would pick another. A path
    /// context means nothing to a socket, so one is refused.
    fn check_path(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        context: &TransportContext,
    ) -> io::Result<()> {
        let local = self.socket.local_addr();
        // A dual-stack IPv6 socket sends to an IPv4 peer at its mapped
        // address, see `Socket::addresses`, so the families are those of the
        // addresses with the mapping undone.
        let source_ip = source.ip().to_canonical();
        let destination_ip = destination.ip().to_canonical();
        let family = match local {
            SocketAddr::V4(_) => {
                source_ip.is_ipv4() && destination_ip.is_ipv4()
            }
            SocketAddr::V6(_) => {
                source_ip.is_ipv4() == destination_ip.is_ipv4()
            }
        };
        let own = source_ip == local.ip().to_canonical()
            || (sys::NAMES_SOURCE && local.ip().is_unspecified());
        let unicast = !source_ip.is_unspecified()
            && !source_ip.is_multicast()
            && !matches!(source_ip, IpAddr::V4(ip) if ip.is_broadcast());
        if source.port() != local.port() || !family || !own || !unicast {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "the socket cannot send from that address",
            ));
        }
        if !context.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a socket takes no path context",
            ));
        }
        Ok(())
    }

    // The endpoint collects completions right after each submission, so an
    // empty queue stays empty until the next one and needs no waker.
    fn poll_complete(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<(WriteId, io::Result<()>)> {
        match self.done.pop_front() {
            Some(id) => Poll::Ready((id, Ok(()))),
            None => Poll::Pending,
        }
    }

    fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}

/// Turns a mapped IPv4 address back into its IPv4 form.
fn unmap(addr: SocketAddr) -> SocketAddr {
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const LOCALHOST: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    // Only the tests on the platforms with `PKTINFO` bind to a wildcard.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ))]
    const UNSPECIFIED: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    const LOCALHOST_V6: SocketAddr =
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);

    fn flow_to(socket: &Socket, remote: SocketAddr) -> Flow {
        Flow { transport: Transport::Udp, local: socket.local, remote }
    }

    #[tokio::test]
    async fn a_datagram_arrives_with_its_flow() {
        let alice = Socket::bind(LOCALHOST).unwrap();
        let bob = Socket::bind(LOCALHOST).unwrap();
        let mut buf = BytesMut::new();

        alice.send(b"hello", &flow_to(&alice, bob.local)).await.unwrap();
        let (datagram, flow) = bob.recv(&mut buf).await.unwrap();

        assert_eq!(&datagram[..], b"hello");
        assert_eq!(flow.transport, Transport::Udp);
        assert_eq!(flow.local, bob.local);
        assert_eq!(flow.remote, alice.local);
    }

    #[tokio::test]
    async fn the_received_flow_is_the_reply_path() {
        let alice = Socket::bind(LOCALHOST).unwrap();
        let bob = Socket::bind(LOCALHOST).unwrap();
        let mut buf = BytesMut::new();

        alice.send(b"ping", &flow_to(&alice, bob.local)).await.unwrap();
        let (_, flow) = bob.recv(&mut buf).await.unwrap();
        bob.send(b"pong", &flow).await.unwrap();
        let (datagram, flow) = alice.recv(&mut buf).await.unwrap();

        assert_eq!(&datagram[..], b"pong");
        assert_eq!(flow.remote, bob.local);
    }

    #[tokio::test]
    async fn datagrams_share_the_read_buffer() {
        let alice = Socket::bind(LOCALHOST).unwrap();
        let bob = Socket::bind(LOCALHOST).unwrap();
        let mut buf = BytesMut::new();
        let flow = flow_to(&alice, bob.local);

        alice.send(b"first", &flow).await.unwrap();
        alice.send(b"second", &flow).await.unwrap();
        let (first, _) = bob.recv(&mut buf).await.unwrap();
        let (second, _) = bob.recv(&mut buf).await.unwrap();

        assert_eq!(&first[..], b"first");
        assert_eq!(&second[..], b"second");
        // The second datagram follows the first in the same allocation.
        let end = first.as_ptr().wrapping_add(first.len());
        assert_eq!(second.as_ptr(), end);
    }

    #[tokio::test]
    async fn an_empty_datagram_is_returned() {
        let alice = Socket::bind(LOCALHOST).unwrap();
        let bob = Socket::bind(LOCALHOST).unwrap();
        let mut buf = BytesMut::new();

        alice.send(b"", &flow_to(&alice, bob.local)).await.unwrap();
        let (datagram, _) = bob.recv(&mut buf).await.unwrap();

        assert!(datagram.is_empty());
    }

    #[tokio::test]
    async fn ipv6_works_the_same() {
        let alice = Socket::bind(LOCALHOST_V6).unwrap();
        let bob = Socket::bind(LOCALHOST_V6).unwrap();
        let mut buf = BytesMut::new();

        alice.send(b"hello", &flow_to(&alice, bob.local)).await.unwrap();
        let (datagram, flow) = bob.recv(&mut buf).await.unwrap();

        assert_eq!(&datagram[..], b"hello");
        assert_eq!(flow.local, bob.local);
        assert_eq!(flow.remote, alice.local);
    }

    // A socket bound to the wildcard address learns the address each datagram
    // came to, on the platforms that report it.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ))]
    #[tokio::test]
    async fn a_wildcard_socket_learns_the_destination() {
        let alice = Socket::bind(LOCALHOST).unwrap();
        let bob = Socket::bind(UNSPECIFIED).unwrap();
        let mut buf = BytesMut::new();
        let to =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bob.local.port());

        alice.send(b"hello", &flow_to(&alice, to)).await.unwrap();
        let (_, flow) = bob.recv(&mut buf).await.unwrap();

        assert_eq!(flow.local, to);
        assert_eq!(flow.remote, alice.local);
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ))]
    #[tokio::test]
    async fn a_wildcard_ipv6_socket_learns_the_destination() {
        let unspecified =
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let alice = Socket::bind(LOCALHOST_V6).unwrap();
        let bob = Socket::bind(unspecified).unwrap();
        let mut buf = BytesMut::new();
        let to =
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), bob.local.port());

        alice.send(b"hello", &flow_to(&alice, to)).await.unwrap();
        let (_, flow) = bob.recv(&mut buf).await.unwrap();

        assert_eq!(flow.local, to);
        assert_eq!(flow.remote, alice.local);
    }

    // Linux routes the whole of 127.0.0.0/8 to the loopback, so a wildcard
    // socket there can pick any of those addresses as its source.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_wildcard_socket_sends_from_the_flow_address() {
        let alice = Socket::bind(UNSPECIFIED).unwrap();
        let bob = Socket::bind(LOCALHOST).unwrap();
        let mut buf = BytesMut::new();
        let source = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5));
        let flow = Flow {
            transport: Transport::Udp,
            local: SocketAddr::new(source, alice.local.port()),
            remote: bob.local,
        };

        alice.send(b"hello", &flow).await.unwrap();
        let (_, flow) = bob.recv(&mut buf).await.unwrap();

        assert_eq!(flow.remote.ip(), source);
        assert_eq!(flow.remote.port(), alice.local.port());
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
        assert_eq!(unmap(LOCALHOST_V6), LOCALHOST_V6);
    }
}
