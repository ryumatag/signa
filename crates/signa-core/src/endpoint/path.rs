/*!
The ways datagrams take besides their addresses.

A backend other than the endpoint's own socket may need more than a source
and a destination to send: the NIC, the MAC addresses or a VLAN tag. It gives
the endpoint that as a [`TransportContext`] with each datagram it receives,
and gets it back in two ways:

* A response goes back with the context its request arrived with. The
  endpoint keeps a copy for as long as the request's reply route or server
  transaction lives, and incoming envelopes show it in [`ReceiveInfo`].
* A request goes on a [`SendPath`] the application prepared, if it names one.
  The path fixes its source, destination, context and the `sent-by` its Via
  names, and the backend checks it once, when it is prepared.

Three addresses are kept apart. The addresses a datagram was observed with
are in [`ReceiveInfo`], and no send path is made from them. A response goes
out from the address its request was sent to, toward where SIP sends it, see
[`WritePath::Reply`]. A request goes out between its path's addresses. The
`sent-by` a request advertises is its path's, or else its source address, and
the endpoint checks the responses to a client transaction against the
`sent-by` that transaction advertised.

Every context the endpoint keeps is a copy of its own, so a backend that
slices it out of a capture buffer does not keep that buffer alive.
[`Builder::context_limits`] bounds the copies and prepared paths alive at
once, for as long as anything holds them. Datagrams without context, which is
all the socket ever gives, take none of it.

[`Builder::context_limits`]: super::Builder::context_limits
*/

use std::{
    fmt, future::Future, io, net::SocketAddr, sync::Arc, time::Instant,
};

use tokio::sync::oneshot;

use super::{
    Endpoint, Error, driver::Command, error::Busy, routing::advertised,
};
use crate::transport::{
    Flow, ReceiveId, Stamp, Transport,
    budget::Budget,
    datagram::{Binding, Path, Prepared, TransportContext},
    unmap,
};

#[cfg(doc)]
use crate::transport::datagram::WritePath;

/// What to send on: the source and destination addresses, the backend's
/// context, and the `sent-by` to advertise.
///
/// [`Endpoint::prepare_path`] turns it into a [`SendPath`] once the UDP
/// backend has accepted it.
///
/// # Example
///
/// ```
/// use signa_core::endpoint::PathSelection;
///
/// let source = "192.0.2.10:5060".parse().unwrap();
/// let next_hop = "198.51.100.7:5060".parse().unwrap();
/// // A host behind a static NAT names its public address in its Via.
/// let selection = PathSelection::new(source, next_hop)
///     .sent_by("203.0.113.5:5060".parse().unwrap());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathSelection {
    source: SocketAddr,
    destination: SocketAddr,
    context: TransportContext,
    sent_by: Option<SocketAddr>,
}

impl PathSelection {
    /// Selects `source` and `destination`, without context. A request on the
    /// path advertises `source` as its `sent-by`.
    pub fn new(source: SocketAddr, destination: SocketAddr) -> PathSelection {
        PathSelection {
            source,
            destination,
            context: TransportContext::default(),
            sent_by: None,
        }
    }

    /// Adds the backend's description of the way to send, in its own format.
    pub fn context(mut self, context: TransportContext) -> PathSelection {
        self.context = context;
        self
    }

    /// Advertises `sent_by` in the Via of a request on the path instead of
    /// the source address, such as the public address of a static NAT.
    ///
    /// The endpoint takes a response to such a request only when its top Via
    /// names this `sent-by` ([RFC 3261 section 18.1.2]). Where the response
    /// goes is up to the peer. Its Via has `rport`, so a peer that supports
    /// [RFC 3581] answers the address and port the request came from, and
    /// only one that does not answers the `sent-by` ([RFC 3261 section
    /// 18.2.2]).
    ///
    /// A Via names no IPv6 zone ([RFC 3261 section 25.1]), so the path drops
    /// the scope ID and flow label of `sent_by`. Its source and destination
    /// keep theirs.
    ///
    /// [RFC 3261 section 18.1.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.1.2
    /// [RFC 3261 section 18.2.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2
    /// [RFC 3261 section 25.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-25.1
    /// [RFC 3581]: https://www.rfc-editor.org/rfc/rfc3581.html#section-4
    pub fn sent_by(mut self, sent_by: SocketAddr) -> PathSelection {
        self.sent_by = Some(sent_by);
        self
    }
}

/// A way to send requests that the UDP backend has accepted.
///
/// [`Endpoint::prepare_path`] makes one, and [`Target::on_path`] sends on it. A
/// path belongs to the endpoint that prepared it. Any other endpoint refuses
/// it with [`Error::is_stale_path`], and nothing derives one from a [`Flow`]
/// or a received [`ReceiveInfo`]. Clones share one path, which counts against
/// [`Builder::context_limits`] until the last of them, and the last
/// transaction sent on it, has dropped.
///
/// [`Target::on_path`]: super::Target::on_path
/// [`Builder::context_limits`]: super::Builder::context_limits
#[derive(Clone)]
pub struct SendPath(pub(super) Arc<Path>);

impl SendPath {
    fn prepared(&self) -> &Prepared {
        self.0.prepared.as_deref().expect("a send path is prepared")
    }

    /// The address requests on the path are sent from.
    pub fn source(&self) -> SocketAddr {
        self.prepared().source
    }

    /// The address requests on the path are sent to.
    pub fn destination(&self) -> SocketAddr {
        self.prepared().destination
    }

    /// The `sent-by` a request on the path advertises in its Via.
    pub fn sent_by(&self) -> SocketAddr {
        self.prepared().sent_by
    }

    /// The backend's context.
    pub fn context(&self) -> &TransportContext {
        &self.0.context
    }

    pub(super) fn binding(&self) -> Binding {
        self.prepared().binding
    }
}

impl fmt::Debug for SendPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendPath")
            .field("source", &self.source())
            .field("destination", &self.destination())
            .field("sent_by", &self.sent_by())
            .field("context", self.context())
            .finish()
    }
}

/// How a message arrived: its ID, when it arrived, the flow it was observed on
/// and the backend's context.
///
/// The ID and the time are made once, where the message first arrived, and
/// stay the same however long it took to reach the envelope:
///
/// * A datagram of the endpoint's own UDP backend arrives when the endpoint
///   takes it from the backend.
/// * A datagram on a shared port arrives when the port's task takes it from
///   the backend, before the application decides about it.
/// * A TCP message arrives when its connection has read all of it and framed
///   it, which is later than its first segment.
///
/// None of them is a kernel or hardware timestamp. The time is the endpoint's
/// clock, the one its timers use.
///
/// These are observed addresses. For an intercepting backend the destination
/// need not be an address of this host. Holding them lets nothing send. A
/// response goes back through the message's reply route, from the address the
/// message was sent to and with the same context.
#[derive(Clone)]
pub struct ReceiveInfo {
    flow: Flow,
    stamp: Stamp,
    path: Option<Arc<Path>>,
}

impl ReceiveInfo {
    pub(super) fn new(
        flow: Flow,
        stamp: Stamp,
        path: Option<Arc<Path>>,
    ) -> ReceiveInfo {
        ReceiveInfo { flow, stamp, path }
    }

    /// The message's ID, which no other message received in this process
    /// has.
    pub fn id(&self) -> ReceiveId {
        self.stamp.id
    }

    /// When the message arrived. See the [type docs](ReceiveInfo) for where
    /// that is on each transport.
    pub fn received_at(&self) -> Instant {
        self.stamp.at
    }

    /// The flow the message arrived on.
    ///
    /// Its remote end is the address the message came from, and its local
    /// end the address it was sent to, the packet's destination. On a shared
    /// port with an intercepting backend, that need not be an address of
    /// this host.
    pub fn flow(&self) -> Flow {
        self.flow
    }

    /// The transport the message arrived over.
    pub fn transport(&self) -> Transport {
        self.flow.transport
    }

    /// The UDP backend's context, empty for TCP and the endpoint's own
    /// socket.
    ///
    /// A clone of its bytes is the caller's own, and the context limits do
    /// not count it.
    pub fn context(&self) -> &TransportContext {
        static EMPTY: TransportContext = TransportContext::EMPTY;
        self.path.as_deref().map_or(&EMPTY, |path| &path.context)
    }

    /// The bytes the copy of the context takes, as the context limits would
    /// count them, for a budget that charges it instead.
    pub(super) fn retained_len(&self) -> usize {
        self.path.as_deref().map_or(0, |path| transient_len(&path.context))
    }
}

impl fmt::Debug for ReceiveInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiveInfo")
            .field("id", &self.stamp.id)
            .field("received_at", &self.stamp.at)
            .field("flow", &self.flow)
            .field("context", self.context())
            .finish()
    }
}

/// Returns `true` if `addr` can be a datagram's source, destination or
/// `sent-by`: a unicast address with a port.
fn unicast(addr: SocketAddr) -> bool {
    let ip = addr.ip();
    addr.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, std::net::IpAddr::V4(ip) if ip.is_broadcast())
}

/// Keeps a received context for a reply route or a server transaction.
///
/// Returns `Some(None)` for an empty context, which costs nothing, and `None`
/// when [`Builder::context_limits`] is full. Control messages, an ACK or a
/// matched CANCEL, may use the quarter of the limits that new requests leave.
///
/// [`Builder::context_limits`]: super::Builder::context_limits
pub(super) fn retain(
    context: &TransportContext,
    limits: &Budget,
    control: bool,
) -> Option<Option<Arc<Path>>> {
    if context.is_empty() {
        return Some(None);
    }
    let charge = Path::charge(context, false);
    let permit = if control {
        limits.acquire(charge)
    } else {
        limits.acquire_request(charge)
    }?;
    Some(Some(Arc::new(Path {
        context: context.detached(),
        prepared: None,
        _permit: Some(permit),
    })))
}

/// The bytes [`transient`] keeps for `context`, as the context limits would
/// count them, without making the copy.
pub(super) fn transient_len(context: &TransportContext) -> usize {
    if context.is_empty() { 0 } else { Path::charge(context, false) }
}

/// A received context for one write made now, such as a stateless 503. It
/// is copied, since the write may wait in the backend's queue, but charged
/// only to the write limits that bound that queue.
pub(super) fn transient(context: &TransportContext) -> Option<Arc<Path>> {
    if context.is_empty() {
        return None;
    }
    Some(Arc::new(Path {
        context: context.detached(),
        prepared: None,
        _permit: None,
    }))
}

impl Endpoint {
    /// Prepares a path for requests from `selection`, once the UDP backend
    /// accepts it.
    ///
    /// The driver asks the backend through [`DatagramIo::check_path`], which
    /// refuses a source it may not send from, a context it cannot read or a
    /// destination it cannot reach. The path then sends with [`Target::on_path`],
    /// for as many requests as the caller likes, until it drops. It does not
    /// look up anything or write to the network.
    ///
    /// The endpoint's own socket accepts a source on its port without
    /// context, at its own address. When it is bound to a wildcard, it also
    /// accepts an address of this host that the caller picks, on Linux,
    /// Android and Apple's systems, where it names the source of each
    /// datagram. Elsewhere, such as on Windows, the kernel picks that source,
    /// so the socket refuses the path.
    ///
    /// # Cancellation
    ///
    /// Dropping the future before it resolves discards the path. Preparing
    /// has no effect on the wire, so preparing again is safe.
    ///
    /// # Errors
    ///
    /// * [`Error::is_unsupported_routing`] on an endpoint without UDP.
    /// * [`Error::is_path_refused`] when the backend refuses the path, or,
    ///   with an `InvalidInput` source, when the source, the destination or
    ///   the `sent-by` is an unspecified, multicast or broadcast address or
    ///   has port 0.
    /// * [`Error::is_busy`] when [`Builder::context_limits`] is full.
    /// * [`Error::is_closed`] once the endpoint has stopped.
    ///
    /// # Example
    ///
    /// A path from one of the addresses of a host whose socket is bound to
    /// a wildcard.
    ///
    /// ```
    /// use std::net::IpAddr;
    ///
    /// use signa_core::endpoint::{
    ///     Endpoint, Error, PathSelection, SendPath, Target,
    /// };
    ///
    /// async fn path_toward(
    ///     endpoint: &Endpoint,
    ///     address: IpAddr,
    ///     next_hop: std::net::SocketAddr,
    /// ) -> Result<Target, Error> {
    ///     let port = endpoint.udp_addr().expect("a UDP endpoint").port();
    ///     let source = std::net::SocketAddr::new(address, port);
    ///     let path: SendPath = endpoint
    ///         .prepare_path(PathSelection::new(source, next_hop))
    ///         .await?;
    ///     Ok(Target::on_path(path))
    /// }
    /// ```
    ///
    /// [`DatagramIo::check_path`]: crate::transport::datagram::DatagramIo::check_path
    /// [`Target::on_path`]: super::Target::on_path
    /// [`Builder::context_limits`]: super::Builder::context_limits
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn prepare_path(
        &self,
        selection: PathSelection,
    ) -> impl Future<Output = Result<SendPath, Error>> + Send + '_ {
        async move {
            let Some(binding) = self.binding else {
                return Err(Error::unsupported_routing());
            };
            if self.commands.is_closed() {
                return Err(Error::closed());
            }
            let path = unchecked(selection, binding, &self.context_limits)?;
            if let Some(port) = &self.port {
                return port.check_path(path).await.map(SendPath);
            }
            let (done, result) = oneshot::channel();
            self.commands
                .send(Command::CheckPath { path, done })
                .map_err(|_| Error::closed())?;
            let path = result.await.map_err(|_| Error::closed())??;
            Ok(SendPath(Arc::new(path)))
        }
    }
}

/// Why [`unchecked`] made no path. An endpoint and a port each report it as
/// an error of their own.
pub(super) enum Unchecked {
    /// An address cannot be a datagram's.
    Refused(io::Error),
    /// The context limits are full.
    Full,
}

impl From<Unchecked> for Error {
    fn from(unchecked: Unchecked) -> Error {
        match unchecked {
            Unchecked::Refused(error) => Error::path_refused(error),
            Unchecked::Full => Error::busy(Busy::Contexts),
        }
    }
}

/// Makes a path of `selection` for `binding`, charged to `limits`, for the
/// backend to check.
///
/// It refuses an address that cannot be a datagram's, and charges what the
/// path keeps as new requests do, see [`Builder::context_limits`].
///
/// [`Builder::context_limits`]: super::Builder::context_limits
pub(super) fn unchecked(
    selection: PathSelection,
    binding: Binding,
    limits: &Budget,
) -> Result<Path, Unchecked> {
    let PathSelection { source, destination, context, sent_by } = selection;
    // A Via names an IPv4 host in its own form, see `Datagram::new`. The
    // source and destination keep an IPv6 scope for the backend. The
    // `sent-by` drops it here, so that `SendPath::sent_by` says what the Via
    // names, which `via_value` makes sure of anyway.
    let source = unmap(source);
    let destination = unmap(destination);
    let sent_by = advertised(sent_by.map_or(source, unmap));
    if ![source, destination, sent_by].into_iter().all(unicast) {
        return Err(Unchecked::Refused(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a path needs unicast addresses with a port",
        )));
    }
    let permit = limits
        .acquire_request(Path::charge(&context, true))
        .ok_or(Unchecked::Full)?;

    Ok(Path {
        context: context.detached(),
        prepared: Some(Box::new(Prepared {
            binding,
            source,
            destination,
            sent_by,
        })),
        _permit: Some(permit),
    })
}
