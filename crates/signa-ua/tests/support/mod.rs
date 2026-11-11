/*!
What the tests share: UAs on loopback endpoints with short timers, and calls
set up for a test to start from.
*/

pub(crate) mod events;
pub(crate) mod flood;
pub(crate) mod message;
pub(crate) mod peer;
pub(crate) mod stand_in;

use std::{net::SocketAddr, time::Duration};

use signa_core::{
    endpoint::{Endpoint, Incoming},
    transaction::Timers,
};
use signa_ua::{Config, Negotiate, Resolve, Session, Ua, UaEvents, attach};

use crate::support::{
    events::invite,
    message::{ack_for, direct_invite, sdp},
    peer::Peer,
    stand_in::Sdp,
};

pub(crate) const WAIT: Duration = Duration::from_secs(2);

pub(crate) fn bind() -> (Endpoint, Incoming) {
    Endpoint::builder().udp("127.0.0.1:0".parse().unwrap()).bind().unwrap()
}

pub(crate) fn config() -> Config {
    Config::new("sip:ua@127.0.0.1").unwrap()
}

/// Timers short enough that a test sees a 2xx retransmitted several times,
/// and its ACK deadline of 64 T1 pass, within a second or two.
pub(crate) fn fast() -> Timers {
    Timers::builder()
        .t1(Duration::from_millis(20))
        .t2(Duration::from_millis(80))
        .build()
        .unwrap()
}

/// Timers for the tests under a flood. The ACK deadline of 64 T1 is 3.2 s,
/// long enough for a loaded test runner, and copies of a 2xx come at most
/// 200 ms apart.
pub(crate) static LOADED: std::sync::LazyLock<Timers> =
    std::sync::LazyLock::new(|| {
        Timers::builder()
            .t1(Duration::from_millis(50))
            .t2(Duration::from_millis(200))
            .build()
            .unwrap()
    });

/// Timers as [`fast`], with a T4 as short, so that a UDP transaction ends
/// soon after its final response and a drain of the endpoint takes about
/// 64 T1, 1.28 s.
pub(crate) fn brisk() -> Timers {
    Timers::builder()
        .t1(Duration::from_millis(20))
        .t2(Duration::from_millis(80))
        .t4(Duration::from_millis(80))
        .build()
        .unwrap()
}

/// A UA on UDP and TCP whose endpoint and configuration run on [`brisk`]
/// timers, its addresses, and another handle to its endpoint.
pub(crate) fn brisk_with<R: Resolve, N: Negotiate>(
    config: Config<R, N>,
) -> (Ua, SocketAddr, SocketAddr, Endpoint) {
    let local = "127.0.0.1:0".parse().unwrap();
    let (endpoint, incoming) = Endpoint::builder()
        .udp(local)
        .tcp(local)
        .timers(brisk())
        .bind()
        .unwrap();
    let (udp, tcp) =
        (endpoint.udp_addr().unwrap(), endpoint.tcp_addr().unwrap());
    let other = endpoint.clone();
    let ua = attach(endpoint, incoming, config.timers(brisk())).unwrap();
    (ua, udp, tcp, other)
}

/// A UA whose endpoint and configuration both run on [`fast`] timers, on
/// UDP and TCP.
pub(crate) fn start_fast() -> (Ua, SocketAddr, SocketAddr) {
    start_fast_with(config())
}

/// [`start_fast`] with `config`, whose timers it sets.
pub(crate) fn start_fast_with<R: Resolve>(
    config: Config<R>,
) -> (Ua, SocketAddr, SocketAddr) {
    let local = "127.0.0.1:0".parse().unwrap();
    let (endpoint, incoming) = Endpoint::builder()
        .udp(local)
        .tcp(local)
        .timers(fast())
        .bind()
        .unwrap();
    let (udp, tcp) =
        (endpoint.udp_addr().unwrap(), endpoint.tcp_addr().unwrap());
    let ua = attach(endpoint, incoming, config.timers(fast())).unwrap();
    (ua, udp, tcp)
}

pub(crate) fn start<R: Resolve>(config: Config<R>) -> (Ua, SocketAddr) {
    let (endpoint, incoming) = bind();
    let address = endpoint.udp_addr().unwrap();
    (attach(endpoint, incoming, config).unwrap(), address)
}

/// A UA with its own endpoint on loopback, whose Contact names its address,
/// so that another UA's requests in the dialog reach it.
pub(crate) fn ua_on(transport: &str) -> (Ua, SocketAddr) {
    let (endpoint, incoming, address) = bound(transport);
    let contact = format!("sip:ua@{address};transport={transport}");
    let config = Config::new(&contact).unwrap().timers(fast());
    (attach(endpoint, incoming, config).unwrap(), address)
}

/// An endpoint on `transport` with [`fast`] timers, and its address.
pub(crate) fn bound(transport: &str) -> (Endpoint, Incoming, SocketAddr) {
    let local = "127.0.0.1:0".parse().unwrap();
    let builder = Endpoint::builder().timers(fast());
    let builder = if transport == "tcp" {
        builder.tcp(local)
    } else {
        builder.udp(local)
    };
    let (endpoint, incoming) = builder.bind().unwrap();
    let address = if transport == "tcp" {
        endpoint.tcp_addr().unwrap()
    } else {
        endpoint.udp_addr().unwrap()
    };
    (endpoint, incoming, address)
}

/// A UA with the [`Sdp`] stand-in as its negotiator, on UDP with
/// [`fast`] timers, and the stand-in's count of calls.
pub(crate) fn negotiating(answer_timeout: Duration) -> (Ua, SocketAddr, Sdp) {
    negotiating_with(answer_timeout, 64)
}

/// [`negotiating`] with at most `answers` prepared at once.
pub(crate) fn negotiating_with(
    answer_timeout: Duration,
    answers: usize,
) -> (Ua, SocketAddr, Sdp) {
    let (endpoint, incoming, address) = bound("udp");
    let sdp = Sdp::default();
    let config = Config::new(&format!("sip:ua@{address}"))
        .unwrap()
        .timers(fast())
        .negotiator(sdp.clone())
        .max_answers(answers)
        .answer_timeout(answer_timeout);
    (attach(endpoint, incoming, config).unwrap(), address, sdp)
}

/// Has the peer call the UA without a proxy, the application accept, and
/// the peer acknowledge, and returns the UA's 2xx and the session.
pub(crate) async fn call_from(
    peer: &Peer,
    ua: SocketAddr,
    events: &mut UaEvents,
    call: &str,
) -> (String, Session) {
    peer.send(&direct_invite(peer.address(), call), ua).await;
    let session = invite(events).await.try_accept(sdp()).unwrap().await;
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    peer.send(&ack_for(&ok, peer.address(), call, 1), ua).await;
    // The UA sends no re-INVITE of its own before the ACK is in (RFC 3261
    // section 14.1), and the 2xx stops once it is.
    peer.drain(Duration::from_millis(60)).await;
    (ok, session.unwrap())
}
