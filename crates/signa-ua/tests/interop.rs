/*!
The UA against SIPp, an independent SIP implementation, in the runs of
`scripts/interop/run`.

These tests do nothing alone, so they are ignored. The script starts each in
a container beside one running SIPp, on a docker network of their own, and
tells it through the environment where it is and what SIPp will do:

* `SIGNA_UA_INTEROP_LOCAL`: the IP address the UA binds and names in its
  Contact.
* `SIGNA_UA_INTEROP_TRANSPORT`: `udp` or `tcp`.
* `SIGNA_UA_INTEROP_CALLS`: how many calls SIPp makes or takes.
* `SIGNA_UA_INTEROP_SCENARIO`: for [`answers_calls_from_sipp`], the
  scenario SIPp plays as the caller.
* `SIGNA_UA_INTEROP_PEER`: for [`calls_sipp`], the address SIPp takes calls
  at.

Each test prints `ready` once the UA listens, and fails if a call does not
go as the scenario has it. The script fails the run if SIPp counts a failed
call.
*/

use std::{env, net::SocketAddr, time::Duration};

use bytes::Bytes;
use signa_core::{HeaderValue, StatusCode, endpoint::Endpoint};
use signa_ua::{
    Config, Description, EndReason, Error, Event, InvitePlan, Ua, UaEvents,
    attach,
};
use tokio::time::{sleep, timeout};

/// How long a step of a call may take, generous for SIPp's pauses.
const STEP: Duration = Duration::from_secs(30);

fn setting(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is set by the script"))
}

fn sdp() -> Description {
    Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from_static(
            b"v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
              t=0 0\r\nm=audio 6000 RTP/AVP 0\r\n",
        ),
    )
}

/// The answer to the re-INVITE of `scenarios/uac_reinvite.xml`, whose
/// offer is `sendonly`: `recvonly`, in the next version of the session
/// (RFC 3264 sections 6.1 and 8).
fn held() -> Description {
    Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from_static(
            b"v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\n\
              t=0 0\r\nm=audio 6000 RTP/AVP 0\r\na=recvonly\r\n",
        ),
    )
}

/// A UA on port 5060 of the address and transport the script names, with
/// RFC 3261's default timers.
fn ua() -> (Ua, String) {
    let local = setting("SIGNA_UA_INTEROP_LOCAL");
    let transport = setting("SIGNA_UA_INTEROP_TRANSPORT");
    let address: SocketAddr = format!("{local}:5060").parse().unwrap();
    let builder = Endpoint::builder();
    let builder = if transport == "tcp" {
        builder.tcp(address)
    } else {
        builder.udp(address)
    };
    let (endpoint, incoming) = builder.bind().unwrap();
    let contact = format!("sip:ua@{address};transport={transport}");
    let config = Config::new(&contact).unwrap();
    (attach(endpoint, incoming, config).unwrap(), transport)
}

fn calls() -> usize {
    setting("SIGNA_UA_INTEROP_CALLS").parse().unwrap()
}

/// The next event for which `wanted` gives something.
async fn event<T>(
    events: &mut UaEvents,
    wanted: impl Fn(Event) -> Option<T>,
) -> T {
    loop {
        let event = timeout(STEP, events.recv())
            .await
            .expect("an event in time")
            .expect("the UA runs");
        if let Some(found) = wanted(event) {
            return found;
        }
    }
}

/// Takes the calls SIPp makes, one at a time, as the scenario has them:
///
/// * `uac`, SIPp's own: the UA accepts, and SIPp's BYE ends the session.
/// * `uac_cancel`: the UA rings, and SIPp's CANCEL gets the INVITE a 487.
/// * `uac_reinvite`: the UA accepts, then accepts SIPp's re-INVITE, and
///   SIPp's BYE ends the session.
#[tokio::test]
#[ignore = "needs SIPp beside it, which scripts/interop/run provides"]
async fn answers_calls_from_sipp() {
    let scenario = setting("SIGNA_UA_INTEROP_SCENARIO");
    let (mut ua, transport) = ua();
    tokio::spawn(ua.driver);
    println!("ready");

    for call in 0..calls() {
        let incoming = event(&mut ua.events, |event| match event {
            Event::Invite(invite) => Some(invite),
            _ => None,
        })
        .await;
        if scenario == "uac_cancel" {
            let ringing = StatusCode::from_u16(180).unwrap();
            incoming.try_provisional(ringing).unwrap().await.unwrap();
            let id = incoming.id();
            event(&mut ua.events, |event| match event {
                Event::Cancelled { invite, .. } if invite == id => Some(()),
                _ => None,
            })
            .await;
            let late = incoming.try_accept(sdp()).unwrap().await;
            assert!(
                matches!(
                    late,
                    Err(Error::AlreadyFinalized | Error::StaleDecision)
                ),
                "{transport} call {call}: {late:?}",
            );
            continue;
        }

        let session = incoming.try_accept(sdp()).unwrap().await.unwrap();
        if scenario == "uac_reinvite" {
            let reinvite = event(&mut ua.events, |event| match event {
                Event::Reinvite(invite) => Some(invite),
                _ => None,
            })
            .await;
            reinvite.try_accept(held()).unwrap().await.unwrap();
        }
        let reason = event(&mut ua.events, |event| match event {
            Event::Ended { session: ended, reason, .. }
                if ended == session =>
            {
                Some(reason)
            }
            _ => None,
        })
        .await;
        assert!(
            matches!(reason, EndReason::RemoteBye { .. }),
            "{transport} call {call}: {reason:?}",
        );
    }
    // The scenarios pause up to 1.5 s after their last message, and over
    // TCP a connection that closes meanwhile fails that call.
    sleep(Duration::from_secs(3)).await;
}

/// Calls SIPp, which plays `scenarios/uas.xml`, one call at a time. Each is
/// answered, acknowledged, and ended by the UA's BYE.
#[tokio::test]
#[ignore = "needs SIPp beside it, which scripts/interop/run provides"]
async fn calls_sipp() {
    let peer = setting("SIGNA_UA_INTEROP_PEER");
    let (mut ua, transport) = ua();
    tokio::spawn(ua.driver);
    println!("ready");

    for call in 0..calls() {
        let plan = InvitePlan::new(
            format!("sip:service@{peer};transport={transport}")
                .parse()
                .unwrap(),
            "sip:ua@signa.invalid".parse().unwrap(),
            sdp(),
        );
        ua.handle.try_invite(plan).unwrap().await.unwrap();
        let session = event(&mut ua.events, |event| match event {
            Event::Confirmed { session, .. } => Some(session),
            _ => None,
        })
        .await;
        let ended = ua.handle.try_terminate(&session).unwrap();
        let result = timeout(STEP, ended).await.expect("a BYE in time");
        assert_eq!(result, Ok(()), "{transport} call {call}");
    }
    // `scenarios/uas.xml` waits 4 s after the 200 to the BYE, and over TCP a
    // connection that closes meanwhile fails that call.
    sleep(Duration::from_secs(5)).await;
}
