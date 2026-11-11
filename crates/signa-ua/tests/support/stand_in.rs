/*!
Stand-ins for what an application plugs into a UA: a negotiator for SDP, and
resolvers that hang, fail or panic on cue.
*/

use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use signa_core::{HeaderValue, endpoint::Target};
use signa_ua::{
    Description, Negotiate, Offer, Query, Resolve, ResolveError,
    StaticResolver,
};
use tokio::sync::Notify;

/// A resolver that never answers for `slow.invalid`, and resolves IP
/// literals otherwise.
pub(crate) struct Slow;

impl Resolve for Slow {
    async fn resolve(&self, query: &Query) -> Result<Target, ResolveError> {
        if query.uri().contains("slow.invalid") {
            std::future::pending::<()>().await;
        }
        StaticResolver::new().resolve(query).await
    }
}

/// A resolver that knows a few host names by heart: `flaky.invalid` fails
/// the first time and then resolves to `peer`, `gated.invalid` waits on the
/// gate, `panic.invalid` panics, and IP literals resolve as they are.
pub(crate) struct Hosts {
    peer: SocketAddr,
    flaky: AtomicUsize,
    pub(crate) gate: Arc<Notify>,
}

impl Hosts {
    pub(crate) fn new(peer: SocketAddr) -> Hosts {
        Hosts {
            peer,
            flaky: AtomicUsize::new(0),
            gate: Arc::new(Notify::new()),
        }
    }
}

impl Resolve for Hosts {
    async fn resolve(&self, query: &Query) -> Result<Target, ResolveError> {
        let udp = signa_core::transport::Transport::Udp;
        if query.uri().contains("flaky.invalid") {
            if self.flaky.fetch_add(1, Ordering::Relaxed) == 0 {
                return Err(ResolveError::Unresolved);
            }
            return Ok(Target::new(udp, self.peer));
        }
        if query.uri().contains("gated.invalid") {
            self.gate.notified().await;
            return Ok(Target::new(udp, self.peer));
        }
        if query.uri().contains("panic.invalid") {
            panic!("a resolver that fails as badly as it can");
        }
        StaticResolver::new().resolve(query).await
    }
}

/// A stand-in for an SDP component, which an application plugs in as its
/// [`Negotiate`] without signa-ua depending on it. It answers each `m=` line
/// of an offer with the same media on a port of its own, or on port 0 when
/// the UA is to end the dialog, which rejects the stream (RFC 3264 section
/// 6). It has no answer for an offer that does not start with `v=0`, and
/// never answers one whose session name is `hang`, as a component that
/// hangs.
#[derive(Clone, Default)]
pub(crate) struct Sdp {
    pub(crate) calls: Arc<AtomicUsize>,
}

impl Negotiate for Sdp {
    fn answer(
        &self,
        offer: &Offer,
    ) -> impl Future<Output = Option<Description>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let text = String::from_utf8(offer.description().body().to_vec());
        let port = if offer.session().is_some() { 49170 } else { 0 };

        async move {
            let text = text.ok().filter(|text| text.starts_with("v=0"))?;
            if text.contains("s=hang") {
                std::future::pending::<()>().await;
            }
            let mut answer = String::from(
                "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\n\
                 c=IN IP4 127.0.0.1\r\nt=0 0\r\n",
            );
            for line in text.lines().filter(|line| line.starts_with("m=")) {
                let mut fields = line[2..].splitn(3, ' ');
                let (media, _, rest) =
                    (fields.next()?, fields.next()?, fields.next()?);
                answer.push_str(&format!("m={media} {port} {rest}\r\n"));
            }
            Some(Description::new(
                HeaderValue::from_static("application/sdp"),
                Bytes::from(answer),
            ))
        }
    }
}
