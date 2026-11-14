/*!
The contract between an endpoint and the backend that carries its UDP
datagrams.

The endpoint's own UDP socket is one [`DatagramIo`] backend. Another one can
take its place through the endpoint builder's `udp_io`, such as an adapter
that reads and writes packets on a NIC itself. The backend moves complete UDP
payloads and their addresses. Everything about SIP stays with the endpoint:
parsing, `received` and `rport`, transactions, timers and retransmissions. An
Ethernet-carried UDP payload still has SIP's UDP semantics.

A backend owns what lies below the payload: MAC addresses, VLAN tags, PPPoE,
IP and UDP headers, checksums and reassembly. It does not retry a write.
Over UDP the transactions retransmit, and a retry below them would be a
second copy the transaction did not ask for.

# Writes

A write goes through two stages, which the endpoint keeps apart even when a
backend finishes both at once:

1. [`DatagramIo::poll_submit`] offers one [`DatagramWrite`]. The backend
   accepts it, refuses it, or says that it cannot take it yet and hands it
   back. An accepted write is never offered again.
2. [`DatagramIo::poll_complete`] reports the local outcome of each accepted
   write once, by its [`WriteId`].

A completion means that one complete datagram was written locally, not that
the peer received it. An adapter with a writer task of its own reports when
that task has written the datagram, not when its queue took it. The endpoint
counts a write against its UDP write limits from the moment it is queued
until its completion.

# Example

A backend that drops every datagram it is given and never receives one.
A real adapter queues the payload for its NIC and reports the completion when
the frame has gone out.

```
use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    task::{Context, Poll},
};

use signa_core::transport::datagram::{
    Capabilities, Datagram, DatagramIo, DatagramWrite, RecvError, Submit,
    WriteId,
};

struct Discard {
    local: SocketAddr,
    done: VecDeque<WriteId>,
}

impl DatagramIo for Discard {
    fn local_addr(&self) -> SocketAddr {
        self.local
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::new(1472)
    }

    fn poll_recv(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Datagram, RecvError>> {
        Poll::Pending
    }

    fn poll_submit(
        &mut self,
        _cx: &mut Context<'_>,
        write: DatagramWrite,
    ) -> Submit {
        self.done.push_back(write.id());
        Submit::Accepted
    }

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
```
*/

use std::{
    error::Error,
    fmt, io,
    net::SocketAddr,
    task::{Context, Poll},
};

use bytes::Bytes;

/// The most bytes a [`TransportContext`] holds.
///
/// Context is a few addresses and tags, not a copy of the frame, and 256 bytes
/// hold a MAC pair, a VLAN stack and a PPPoE session with room to spare. The
/// limit bounds what the endpoint keeps for each datagram.
pub const MAX_CONTEXT_LEN: usize = 256;

/// A backend that sends and receives UDP payloads for one endpoint.
///
/// The endpoint's driver owns the backend and polls it from its own task, so
/// a backend that needs a task of its own, such as a NIC reader, talks to it
/// through channels and wakes the waker it was last polled with. Every
/// `Pending` registers that waker. Nothing here retries a write.
///
/// The driver may also poll with a waker that does nothing, to send at once
/// when the backend can take a datagram right away. It polls again with its
/// real waker before it waits, so a backend only has to keep the last waker
/// it was given.
///
/// See the [module docs](self) for the stages of a write.
pub trait DatagramIo: Send + 'static {
    /// The address the endpoint sends from and names in its `Via` headers.
    ///
    /// The endpoint reads it when it is bound and expects it not to change.
    /// A backend other than the endpoint's own socket must name one address
    /// and port, not a wildcard.
    fn local_addr(&self) -> SocketAddr;

    /// What the backend can do. The endpoint reads it when it is bound and
    /// expects it not to change.
    fn capabilities(&self) -> Capabilities;

    /// Polls for the next received datagram.
    ///
    /// A datagram is the whole UDP payload. One that did not fit the
    /// backend's buffer is [`RecvError::Truncated`], never a shorter payload.
    /// The endpoint discards both errors, counts them, and polls again.
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Datagram, RecvError>>;

    /// Offers one datagram to send.
    ///
    /// [`Submit::Accepted`] takes the write. Its outcome comes once from
    /// [`DatagramIo::poll_complete`]. [`Submit::Pending`] hands it back
    /// untouched and registers the waker, which the backend wakes when it can
    /// take a write again. [`Submit::Rejected`] hands it back with the error
    /// that kept the backend from taking it, such as a source address it may
    /// not send from. The endpoint never offers an accepted write again, and
    /// offers its writes in [`WriteId`] order.
    fn poll_submit(
        &mut self,
        cx: &mut Context<'_>,
        write: DatagramWrite,
    ) -> Submit;

    /// Polls for the outcome of an accepted write.
    ///
    /// Each accepted [`WriteId`] is reported once, in any order. `Ok` means
    /// the datagram was written whole to the local network, `Err` that it was
    /// not.
    fn poll_complete(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<(WriteId, io::Result<()>)>;

    /// Polls the backend to close.
    ///
    /// The endpoint calls it once it has stopped, after its last write was
    /// offered. A graceful shutdown first waits for the outstanding writes to
    /// complete. At the shutdown deadline it calls this with writes still
    /// outstanding instead.
    ///
    /// Before it returns `Ready`, the backend finishes or fails every write
    /// it accepted, so that [`DatagramIo::poll_complete`] reports each one
    /// without waiting, and stops every task of its own that could still
    /// send. The endpoint then collects those outcomes and drops the backend.
    /// It treats a write left unreported as lost.
    ///
    /// Closing is bounded by the same deadline. A backend still closing when
    /// it passes gets one more poll, and is then dropped without one, so its
    /// `Drop` must stop what `poll_close` would have stopped.
    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<()>;
}

/// What a [`DatagramIo`] backend can do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Capabilities {
    /// The largest payload the backend sends in one datagram. The endpoint
    /// fails a larger write before offering it.
    pub max_payload: usize,
}

impl Capabilities {
    /// Describes a backend that sends payloads of up to `max_payload` bytes.
    pub fn new(max_payload: usize) -> Capabilities {
        Capabilities { max_payload }
    }
}

/// One received UDP payload with its addresses.
///
/// The addresses are the ones in the packet. For an adapter that intercepts
/// traffic, the destination need not be an address of this host.
pub struct Datagram {
    payload: Bytes,
    source: SocketAddr,
    destination: SocketAddr,
    context: TransportContext,
}

impl Datagram {
    /// A datagram from `source` to `destination`, with no context.
    ///
    /// Report an IPv4 peer of a dual-stack socket by its IPv4 address, not its
    /// IPv4-mapped IPv6 form, since a `Via` names it that way.
    pub fn new(
        payload: Bytes,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Datagram {
        Datagram {
            payload,
            source,
            destination,
            context: TransportContext::default(),
        }
    }

    /// Attaches the backend's own description of how the datagram arrived.
    pub fn with_context(mut self, context: TransportContext) -> Datagram {
        self.context = context;
        self
    }

    /// The UDP payload.
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Where the datagram came from.
    pub fn source(&self) -> SocketAddr {
        self.source
    }

    /// Where the datagram was sent to.
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// The backend's context.
    pub fn context(&self) -> &TransportContext {
        &self.context
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn into_parts(
        self,
    ) -> (Bytes, SocketAddr, SocketAddr, TransportContext) {
        (self.payload, self.source, self.destination, self.context)
    }
}

impl fmt::Debug for Datagram {
    // The payload is SIP traffic, which can carry credentials. Only its length
    // goes into a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Datagram")
            .field("len", &self.payload.len())
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("context", &self.context)
            .finish()
    }
}

/// A backend's description of how a datagram arrived, such as the NIC, MAC
/// addresses, VLAN tags or PPPoE session.
///
/// The bytes are the backend's own format, and signa does not read them.
/// There are at most [`MAX_CONTEXT_LEN`] of them. Copy them out of a large
/// capture buffer rather than slicing it, since a slice keeps the whole
/// buffer alive.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct TransportContext(Bytes);

impl TransportContext {
    /// Wraps the backend's bytes.
    ///
    /// # Errors
    ///
    /// Fails if there are more than [`MAX_CONTEXT_LEN`] bytes.
    pub fn new(bytes: Bytes) -> Result<TransportContext, ContextTooLong> {
        if bytes.len() > MAX_CONTEXT_LEN {
            return Err(ContextTooLong(bytes.len()));
        }
        Ok(TransportContext(bytes))
    }

    /// The backend's bytes.
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// The number of bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for TransportContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TransportContext").field(&self.0.len()).finish()
    }
}

/// The error of a [`TransportContext`] longer than [`MAX_CONTEXT_LEN`], with
/// its length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextTooLong(usize);

impl ContextTooLong {
    /// The length of the bytes that were refused.
    pub fn context_len(&self) -> usize {
        self.0
    }
}

impl fmt::Display for ContextTooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a transport context of {} bytes is longer than {MAX_CONTEXT_LEN}",
            self.0
        )
    }
}

impl Error for ContextTooLong {}

/// Names one write from its submission to its completion.
///
/// The endpoint numbers its writes in the order it makes them. A backend
/// reports the outcome of an accepted write by its ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WriteId(u64);

impl WriteId {
    #[cfg(feature = "tokio")]
    pub(crate) fn new(n: u64) -> WriteId {
        WriteId(n)
    }
}

/// One datagram for a backend to send.
pub struct DatagramWrite {
    id: WriteId,
    payload: Bytes,
    source: SocketAddr,
    destination: SocketAddr,
}

impl DatagramWrite {
    #[cfg(feature = "tokio")]
    pub(crate) fn new(
        id: WriteId,
        payload: Bytes,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> DatagramWrite {
        DatagramWrite { id, payload, source, destination }
    }

    /// The ID to report the write's outcome by.
    pub fn id(&self) -> WriteId {
        self.id
    }

    /// The UDP payload, which the backend sends unchanged.
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// The address to send from.
    ///
    /// A reply goes out from the address its request came to, and a request
    /// from [`DatagramIo::local_addr`]. The endpoint's own socket may get an
    /// unspecified IP address here, where it lets the kernel choose.
    pub fn source(&self) -> SocketAddr {
        self.source
    }

    /// The address to send to.
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// Takes the payload, once the ID and addresses have been read.
    pub fn into_payload(self) -> Bytes {
        self.payload
    }
}

impl fmt::Debug for DatagramWrite {
    // See the `Debug` of `Datagram`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramWrite")
            .field("id", &self.id)
            .field("len", &self.payload.len())
            .field("source", &self.source)
            .field("destination", &self.destination)
            .finish()
    }
}

/// What [`DatagramIo::poll_submit`] did with a write.
#[derive(Debug)]
#[must_use = "a write handed back is lost if it is dropped"]
pub enum Submit {
    /// The backend took the write and reports its outcome later.
    Accepted,
    /// The backend cannot take a write now and will wake the task when it can.
    /// The write comes back untouched.
    Pending(DatagramWrite),
    /// The backend refused the write, which comes back with the reason.
    Rejected(DatagramWrite, io::Error),
}

/// Why a backend returned no datagram.
#[derive(Debug)]
#[non_exhaustive]
pub enum RecvError {
    /// A datagram was larger than the backend could take, and what it did take
    /// is not the whole payload.
    Truncated,
    /// Receiving failed.
    Io(io::Error),
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvError::Truncated => f.write_str("the datagram was truncated"),
            RecvError::Io(_) => f.write_str("receiving a datagram failed"),
        }
    }
}

impl Error for RecvError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RecvError::Truncated => None,
            RecvError::Io(error) => Some(error),
        }
    }
}

impl From<io::Error> for RecvError {
    fn from(error: io::Error) -> RecvError {
        RecvError::Io(error)
    }
}
