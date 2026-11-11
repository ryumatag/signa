/*!
`UaHandle::shutdown` in its two phases. The UA ends its work, or lets the
application end it, while its endpoint still takes the requests that work
needs. Then it shuts the endpoint down, both phases by one deadline. The
statuses and the order are signa-ua policy where no RFC is named.
*/

mod deadline;
mod drain;
mod terminate;

use std::{net::SocketAddr, time::Duration};

use signa_core::{endpoint::Endpoint, transaction::Timers};
use signa_ua::{
    Config, Event, InvitePlan, Negotiate, Resolve, Session, ShutdownReport,
    Ua, UaEvents, attach,
};
use tokio::time::timeout;

use crate::support::{
    events::{event, invite},
    message::sdp,
};

/// Timers as [`fast`](crate::support::fast), with a T4 as short, so that a
/// UDP transaction ends soon after its final response and a drain of the
/// endpoint takes about 64 T1, 1.28 s.
fn brisk() -> Timers {
    Timers::builder()
        .t1(Duration::from_millis(20))
        .t2(Duration::from_millis(80))
        .t4(Duration::from_millis(80))
        .build()
        .unwrap()
}

/// A UA on UDP and TCP whose endpoint and configuration run on [`brisk`]
/// timers, its addresses, and another handle to its endpoint.
fn brisk_with<R: Resolve, N: Negotiate>(
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

/// [`ua_on`](crate::support::ua_on) with `timers`, for both its endpoint
/// and its configuration.
fn ua_timed(transport: &str, timers: Timers) -> (Ua, SocketAddr) {
    let local = "127.0.0.1:0".parse().unwrap();
    let builder = Endpoint::builder().timers(timers);
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
    let contact = format!("sip:ua@{address};transport={transport}");
    let config = Config::new(&contact).unwrap().timers(timers);
    (attach(endpoint, incoming, config).unwrap(), address)
}

/// Has the `caller` UA call the UA at `address` over `transport`, whose
/// application accepts, and returns the caller's session and the callee's,
/// once the ACK is in.
async fn two_ua_call(
    caller: &signa_ua::UaHandle,
    caller_events: &mut UaEvents,
    callee_events: &mut UaEvents,
    address: SocketAddr,
    transport: &str,
) -> (Session, Session) {
    let plan = InvitePlan::new(
        format!("sip:ua@{address};transport={transport}").parse().unwrap(),
        "sip:caller@127.0.0.1".parse().unwrap(),
        sdp(),
    );
    caller.try_invite(plan).unwrap().await.unwrap();
    let answered =
        invite(callee_events).await.try_accept(sdp()).unwrap().await.unwrap();
    let calling = event(caller_events, |event| match event {
        Event::Confirmed { session, .. } => Some(session),
        _ => None,
    })
    .await;
    // The ACK goes at once, and stops the 2xx.
    tokio::time::sleep(Duration::from_millis(100)).await;
    (calling, answered)
}

/// Waits for the report of a shutdown, which must come within `wait`.
async fn report_within(
    shutdown: signa_ua::UaShutdown,
    wait: Duration,
) -> ShutdownReport {
    timeout(wait, shutdown).await.expect("a report in time").unwrap()
}
