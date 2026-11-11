/*!
The runtime's own contract, which no RFC sets: one receiver per endpoint,
handles that belong to their UA, admission, what dropping a handle or the
driver does, and the driver going on while the application or a resolver
stalls.
*/

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use signa_core::{
    Request, StatusCode,
    endpoint::{Endpoint, Reception, Target},
};
use signa_ua::{
    AttachError, Error, Event, InvitePlan, Query, Resolve, ResolveError,
    SessionPhase, StaticResolver, Ua, attach,
};
use tokio::{sync::Notify, time::timeout};

use crate::support::{
    WAIT, bind, config,
    events::{event, invite},
    fast,
    message::{answer, header, invite_to_ua, plan_to, sdp},
    peer::Peer,
    stand_in::{Hosts, Slow},
    start, start_fast, start_fast_with, ua_on,
};

/// An INVITE to `to` as the endpoint takes it, without the UA.
fn invite_from_ua(to: &str, call: &str) -> Request<Bytes> {
    Request::builder()
        .method("INVITE")
        .uri(format!("sip:peer@{to}").as_str())
        .header("To", format!("<sip:peer@{to}>").as_str())
        .header("From", format!("<sip:ua@127.0.0.1>;tag=ua-{call}").as_str())
        .header("Call-ID", call)
        .header("CSeq", "1 INVITE")
        .header("Max-Forwards", "70")
        .header("Contact", "<sip:ua@127.0.0.1>")
        .header("Content-Type", "application/sdp")
        .body(Bytes::from_static(b"v=0\r\n"))
        .unwrap()
}

/// The UA takes the only receiver of its endpoint, and refuses an endpoint
/// that creates no transactions.
#[tokio::test]
async fn single_incoming_owner() {
    let (endpoint, incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .reception(Reception::Stateless)
        .bind()
        .unwrap();
    assert_eq!(
        attach(endpoint, incoming, config()).unwrap_err(),
        AttachError::Stateless,
    );

    let (endpoint, incoming) = bind();
    // `incoming` moves into the UA, so nothing else can receive from it.
    assert!(attach(endpoint, incoming, config()).is_ok());
}

/// The application accepts and drops the operation at once. The 200 still
/// goes out, with the dialog's Record-Route and the UA's Contact.
#[tokio::test]
async fn waiting_operation_drop_does_not_withdraw_accepted_command() {
    let (mut ua, address) = start(config());
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "drop-wait"), address).await;
    let invite = invite(&mut ua.events).await;
    drop(invite.try_accept(sdp()).unwrap());

    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert!(header(&ok, "To")[0].contains(";tag="));
    assert_eq!(header(&ok, "Contact"), ["<sip:ua@127.0.0.1>"]);
    assert_eq!(header(&ok, "Record-Route"), ["<sip:proxy.example.com;lr>"]);
    assert_eq!(header(&ok, "Allow"), ["INVITE, ACK, CANCEL, BYE, OPTIONS"]);
}

/// Dropping every handle of the application sends nothing on its own. The
/// UAS keeps its responder, so no 500 follows the 200, and the UAC keeps its
/// client transaction, so the 2xx still gets its ACK.
#[tokio::test]
async fn observer_drop_does_not_drop_responder_or_client_control() {
    let (mut ua, address) = start(config());
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "drop-uas"), address).await;
    let invite = invite(&mut ua.events).await;
    // The session handle goes at once.
    let _ = invite.try_accept(sdp()).unwrap().await.unwrap();
    peer.recv_starting("SIP/2.0 200").await;
    peer.quiet("SIP/2.0 500", Duration::from_millis(300)).await;

    // So does the attempt handle, and the events with it.
    let _ = ua
        .handle
        .try_invite(plan_to(&peer.address().to_string(), "drop-uac"))
        .unwrap()
        .await
        .unwrap();
    drop(ua.events);

    let (request, from) = peer.recv_starting("INVITE").await;
    let contact = format!("sip:peer@{}", peer.address());
    peer.send(&answer(&request, "200", "peer", &contact), from).await;

    let (ack, _) = peer.recv_starting("ACK").await;
    let number = header(&request, "CSeq")[0].replace("INVITE", "ACK");
    assert_eq!(header(&ack, "CSeq"), [number]);
    assert_eq!(header(&ack, "Call-ID"), header(&request, "Call-ID"));
    // The To is the Request-URI without its port, which a To may not have
    // (Table 1 of RFC 3261 section 19.1.1).
    assert_eq!(header(&ack, "To"), ["<sip:peer@127.0.0.1>;tag=peer"]);
    peer.quiet("CANCEL", Duration::from_millis(300)).await;
}

/// The ACK of one dialog waits for its next hop, which never resolves. The
/// ACK of another dialog goes out meanwhile.
#[tokio::test]
async fn slow_resolver_does_not_block_other_dialog_ack() {
    let (ua, _) = start(config().resolver(Slow));
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    for call in ["slow", "fast"] {
        ua.handle.try_invite(plan_to(&to, call)).unwrap().await.unwrap();
    }
    let (first, from) = peer.recv_starting("INVITE").await;
    let (second, _) = peer.recv_starting("INVITE").await;
    let (slow, fast) = if header(&first, "Subject") == ["slow"] {
        (first, second)
    } else {
        (second, first)
    };

    peer.send(&answer(&slow, "200", "s", "sip:peer@slow.invalid"), from).await;
    peer.send(&answer(&fast, "200", "f", &format!("sip:peer@{to}")), from)
        .await;

    let (ack, _) = peer.recv_starting("ACK").await;
    assert_eq!(header(&ack, "Call-ID"), header(&fast, "Call-ID"));
}

/// With a command queue of one and the driver not yet running, a second
/// INVITE is refused and handed back. Nothing goes out for it, then or later.
#[tokio::test]
async fn command_queue_full_returns_busy_without_state_mutation() {
    let (ua, _) = start(config().command_capacity(1));
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    let first = ua.handle.try_invite(plan_to(&to, "first")).unwrap();
    let refused = ua.handle.try_invite(plan_to(&to, "second")).unwrap_err();

    assert_eq!(refused.error(), Error::Busy);
    let returned = refused.into_inner();
    assert!(format!("{returned:?}").contains("second"));

    tokio::spawn(ua.driver);
    first.await.unwrap();
    let (request, _) = peer.recv_starting("INVITE").await;
    assert_eq!(header(&request, "Subject"), ["first"]);
    peer.quiet("INVITE", Duration::from_millis(300)).await;
}

/// A resolver that waits until told to resolve.
struct Gate(Arc<Notify>);

impl Resolve for Gate {
    async fn resolve(&self, query: &Query) -> Result<Target, ResolveError> {
        self.0.notified().await;
        StaticResolver::new().resolve(query).await
    }
}

/// Dropping the driver stops the UA at once. An operation in flight fails
/// with `DriverStopped`, the handle takes nothing more, the copies of a 2xx
/// stop, and the endpoint shuts down with it.
#[tokio::test]
async fn driver_drop_is_forced_stop_not_graceful_shutdown() {
    let local = "127.0.0.1:0".parse().unwrap();
    let (endpoint, incoming) =
        Endpoint::builder().udp(local).timers(fast()).bind().unwrap();
    let address = endpoint.udp_addr().unwrap();
    let gate = Arc::new(Notify::new());
    let config = config().resolver(Gate(gate)).timers(fast());
    let mut ua = attach(endpoint.clone(), incoming, config).unwrap();
    let driver = tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    // A 2xx the peer never acknowledges goes out again and again.
    peer.send(&invite_to_ua(peer.address(), "copies"), address).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    peer.recv_starting("SIP/2.0 200").await;
    peer.recv_starting("SIP/2.0 200").await;
    // The INVITE waits on the gate, so the driver has taken it once the
    // event of the 2xx, which comes after, is in.
    let pending = ua.handle.try_invite(plan_to(&to, "stuck")).unwrap();
    peer.send(&invite_to_ua(peer.address(), "marker"), address).await;
    invite(&mut ua.events).await;
    driver.abort();

    assert_eq!(
        timeout(WAIT, pending).await.unwrap().unwrap_err(),
        Error::DriverStopped
    );
    let refused = ua.handle.try_invite(plan_to(&to, "late")).unwrap_err();
    assert_eq!(refused.error(), Error::Closed);
    let target =
        Target::new(signa_core::transport::Transport::Udp, peer.address());
    let error = endpoint
        .start(invite_from_ua(&to, "direct"), target)
        .await
        .unwrap_err();
    assert!(error.is_closed());
    peer.drain(Duration::from_millis(50)).await;
    peer.quiet("SIP/2.0 200", Duration::from_millis(300)).await;
}

/// An INVITE whose decision is dropped gets a 500, and a rejected one the
/// status the application chose.
#[tokio::test]
async fn an_undecided_invite_gets_a_500_and_a_rejected_one_its_status() {
    let (mut ua, address) = start(config());
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "dropped"), address).await;
    drop(invite(&mut ua.events).await);
    let (response, _) = peer.recv_starting("SIP/2.0 500").await;
    assert_eq!(header(&response, "Call-ID"), ["dropped"]);
    assert!(header(&response, "To")[0].contains(";tag="));

    peer.send(&invite_to_ua(peer.address(), "busy"), address).await;
    let busy = StatusCode::from_u16(486).unwrap();
    invite(&mut ua.events).await.try_reject(busy).unwrap().await.unwrap();
    let (response, _) = peer.recv_starting("SIP/2.0 486").await;
    assert_eq!(header(&response, "Call-ID"), ["busy"]);
}

/// A rejection needs a final status other than a 2xx, and a refused one
/// leaves the decision with the application.
#[tokio::test]
async fn an_invalid_rejection_hands_the_invite_back() {
    let (mut ua, address) = start(config());
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "retry"), address).await;
    let invite = invite(&mut ua.events).await;
    let refused = invite.try_reject(StatusCode::OK).unwrap_err();
    assert_eq!(refused.error(), Error::InvalidInput);

    refused.into_inner().try_accept(sdp()).unwrap().await.unwrap();
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(header(&ok, "Call-ID"), ["retry"]);
}

/// A resolution that never ends counts as unresolved after the timeout, and
/// frees its job. With one job slot, a final response still gets out after
/// it.
#[tokio::test]
async fn a_hung_resolver_gives_up_and_frees_its_job() {
    let config = config()
        .resolver(Slow)
        .max_jobs(1)
        .resolve_timeout(Duration::from_millis(100));
    let (mut ua, address) = start(config);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    let hung = ua.handle.try_invite(plan_to("slow.invalid", "hung"));
    peer.send(&invite_to_ua(peer.address(), "behind"), address).await;
    let invite = invite(&mut ua.events).await;
    let accepted = invite.try_accept(sdp()).unwrap();

    assert_eq!(
        timeout(WAIT, hung.unwrap()).await.unwrap().unwrap_err(),
        Error::Unroutable,
    );
    let (ok, _) = peer.recv_starting("SIP/2.0 200").await;
    assert_eq!(header(&ok, "Call-ID"), ["behind"]);
    timeout(WAIT, accepted).await.unwrap().unwrap();
}

/// Each running operation holds one of `max_operations` places, so one
/// beyond it is refused and handed back. The place comes back with the
/// outcome.
#[tokio::test]
async fn operations_beyond_the_limit_are_busy_until_one_ends() {
    let (ua, _) = start(config().max_operations(1));
    let peer = Peer::new().await;
    let to = peer.address().to_string();

    let first = ua.handle.try_invite(plan_to(&to, "first")).unwrap();
    let refused = ua.handle.try_invite(plan_to(&to, "second")).unwrap_err();
    assert_eq!(refused.error(), Error::Busy);

    tokio::spawn(ua.driver);
    first.await.unwrap();
    ua.handle.try_invite(refused.into_inner()).unwrap().await.unwrap();
}

/// A resolver that panics fails the INVITE it was resolving, and the UA
/// goes on with the next one.
#[tokio::test]
async fn a_panicking_resolver_fails_only_its_request() {
    let peer = Peer::new().await;
    let (ua, _) = start(config().resolver(Hosts::new(peer.address())));
    tokio::spawn(ua.driver);

    let failed = ua.handle.try_invite(plan_to("panic.invalid", "panic"));
    assert_eq!(
        timeout(WAIT, failed.unwrap()).await.unwrap().unwrap_err(),
        Error::Internal,
    );
    let to = peer.address().to_string();
    ua.handle.try_invite(plan_to(&to, "after")).unwrap().await.unwrap();
    peer.recv_starting("INVITE").await;
}

/// Once nobody reads the events, nobody can decide an INVITE, and a new one
/// gets a 503. A request the UA refuses anyway still gets its own status,
/// such as the 481 of a dialog the UA does not know.
#[tokio::test]
async fn an_invite_nobody_can_decide_gets_a_503_after_its_checks() {
    let (ua, udp, _) = start_fast();
    tokio::spawn(ua.driver);
    drop(ua.events);
    let peer = Peer::new().await;
    let unknown = invite_to_ua(peer.address(), "unknown")
        .replace("To: <sip:ua@127.0.0.1>", "To: <sip:ua@127.0.0.1>;tag=gone");

    peer.send(&invite_to_ua(peer.address(), "unheard"), udp).await;
    let (response, _) = peer.recv_starting("SIP/2.0 503").await;
    assert_eq!(header(&response, "Call-ID"), ["unheard"]);

    peer.send(&unknown, udp).await;
    let (response, _) = peer.recv_starting("SIP/2.0 481").await;
    assert_eq!(header(&response, "Call-ID"), ["unknown"]);
}

/// INVITEs this UA sends each set a place in the event queue aside for
/// their end, apart from the places of other events. With every attempt in
/// flight, an incoming INVITE still reaches the application.
#[tokio::test]
async fn invites_in_flight_do_not_crowd_out_other_events() {
    let config = config().event_capacity(1).max_attempts(2);
    let (mut ua, udp, _) = start_fast_with(config);
    tokio::spawn(ua.driver);
    let callee = Peer::new().await;
    let caller = Peer::new().await;
    let to = callee.address().to_string();

    for call in ["first", "second"] {
        ua.handle.try_invite(plan_to(&to, call)).unwrap().await.unwrap();
    }
    caller.send(&invite_to_ua(caller.address(), "incoming"), udp).await;

    let incoming = invite(&mut ua.events).await;
    assert_eq!(
        incoming.request().headers().get("Call-ID").unwrap(),
        "incoming"
    );
}

/// An accepted INVITE waits for its ACK outside the limit of pending
/// INVITEs and of attempts. Another INVITE still reaches the application,
/// and the UA can still send one.
#[tokio::test]
async fn invites_awaiting_ack_leave_room_for_others() {
    let config = config().max_pending_invites(1).max_attempts(1);
    let (mut ua, udp, _) = start_fast_with(config);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;

    peer.send(&invite_to_ua(peer.address(), "unacked"), udp).await;
    invite(&mut ua.events).await.try_accept(sdp()).unwrap().await.unwrap();
    peer.send(&invite_to_ua(peer.address(), "next"), udp).await;
    invite(&mut ua.events).await;

    let to = peer.address().to_string();
    ua.handle.try_invite(plan_to(&to, "outgoing")).unwrap().await.unwrap();
}

/// Each UA numbers its sessions and attempts from the same start, so the
/// handles of one would name the other's if a UA took them. A UA refuses
/// the handles of another, before anything is admitted, and nothing goes
/// on the wire for its own session either.
#[tokio::test]
async fn handles_of_another_ua_are_refused() {
    let (Ua { handle: caller, events: mut caller_events, driver }, _) =
        ua_on("udp");
    tokio::spawn(driver);
    let (Ua { handle: callee, events: mut callee_events, driver }, address) =
        ua_on("udp");
    tokio::spawn(driver);
    let plan = InvitePlan::new(
        format!("sip:ua@{address}").parse().unwrap(),
        "sip:caller@127.0.0.1".parse().unwrap(),
        sdp(),
    );

    let attempt = caller.try_invite(plan).unwrap().await.unwrap();
    let answered = invite(&mut callee_events)
        .await
        .try_accept(sdp())
        .unwrap()
        .await
        .unwrap();
    let calling = event(&mut caller_events, |event| match event {
        Event::Confirmed { session, .. } => Some(session),
        _ => None,
    })
    .await;

    let refused = callee.try_terminate(&calling).unwrap_err();
    assert_eq!(refused.error(), Error::InvalidInput);
    assert_eq!(
        callee.try_cancel(&attempt).unwrap_err().error(),
        Error::InvalidInput
    );
    assert_eq!(
        callee.try_abandon(&attempt).unwrap_err().error(),
        Error::InvalidInput
    );
    assert_eq!(callee.snapshot(&calling).await, Err(Error::InvalidInput));
    assert_eq!(
        callee.attempt_snapshot(&attempt).await,
        Err(Error::InvalidInput)
    );
    assert_ne!(calling.id(), answered.id());

    tokio::time::sleep(Duration::from_millis(100)).await;
    for (handle, session) in [(&caller, &calling), (&callee, &answered)] {
        let snapshot = handle.snapshot(session).await.unwrap().unwrap();
        assert_eq!(snapshot.phase, SessionPhase::Established);
    }
}
