/*!
A UA that shuts down with calls under way, through signa-ua, on the loopback.

A phone calls a PBX twice. The PBX answers the first call and leaves the
second ringing, then shuts down with [`ShutdownMode::Terminate`], as a server
taken out of service would. The UA ends what it has, as a user who hangs up
would (RFC 3261 section 15):

* The INVITE the application has not decided gets a 503.
* The session gets a BYE, and ends with [`EndReason::Shutdown`].
* Once those have ended, the UA shuts its endpoint down, and the report
  counts what the shutdown ended.

The phone sees the second call fail and the first end with the PBX's BYE,
and then drains, with nothing left to end.

The example checks each step and fails otherwise. It takes about 35 s with
or without `--t1-ms 50`. The phone's shutdown waits for its INVITE's
transaction to absorb copies of the 503, which takes Timer D, at least 32 s
on UDP whatever T1 is (RFC 3261 section 17.1.1.2).
*/

use std::time::Duration;

use bytes::Bytes;
use signa::{
    HeaderValue, StatusCode,
    endpoint::Endpoint,
    transaction::Timers,
    ua::{
        AttemptResult, Config, Description, EndReason, Error, Event,
        InvitePlan, ShutdownMode, ShutdownOutcome, Ua, UaEvents, attach,
    },
};
use tokio::time::timeout;

#[tokio::main]
async fn main() {
    let timers = timers();
    let (phone, _) = ua(timers, "phone");
    let (pbx, pbx_address) = ua(timers, "pbx");
    let Ua { handle: phone, events: mut phone_events, driver } = phone;
    let phone_driver = tokio::spawn(driver);
    let Ua { handle: pbx, events: mut pbx_events, driver } = pbx;
    let pbx_driver = tokio::spawn(driver);

    let plan = || {
        InvitePlan::new(
            format!("sip:pbx@{pbx_address}").parse().unwrap(),
            "sip:phone@127.0.0.1".parse().unwrap(),
            sdp(OFFER),
        )
    };

    // The first call: the PBX answers it.
    let answered = phone.try_invite(plan()).unwrap().await.unwrap();
    let invite = next(&mut pbx_events, |event| match event {
        Event::Invite(invite) => Some(invite),
        _ => None,
    })
    .await;
    let pbx_session = invite.try_accept(sdp(ANSWER)).unwrap().await.unwrap();
    let session = next(&mut phone_events, |event| match event {
        Event::Confirmed { session, .. } => Some(session),
        _ => None,
    })
    .await;
    println!("phone: in the first call");

    // The second call: the PBX rings and holds it, undecided.
    let ringing = phone.try_invite(plan()).unwrap().await.unwrap();
    let invite = next(&mut pbx_events, |event| match event {
        Event::Invite(invite) => Some(invite),
        _ => None,
    })
    .await;
    let status = StatusCode::from_u16(180).unwrap();
    invite.try_provisional(status).unwrap().await.unwrap();
    next(&mut phone_events, |event| match event {
        Event::Early { attempt, .. } if attempt == ringing.id() => Some(()),
        _ => None,
    })
    .await;
    println!("phone: the second call rings");

    // The PBX shuts down, and ends both. Its application keeps the second
    // INVITE, which the UA answers all the same.
    let shutdown = pbx.shutdown(ShutdownMode::Terminate, LIMIT);
    let reason = next(&mut pbx_events, |event| match event {
        Event::Ended { session: ended, reason, .. }
            if ended == pbx_session =>
        {
            Some(reason)
        }
        _ => None,
    })
    .await;
    assert_eq!(reason, EndReason::Shutdown);
    let report = shutdown.await.unwrap();
    assert_eq!(report.outcome, ShutdownOutcome::Drained);
    assert_eq!((report.ended, report.terminated), (1, 1));
    assert_eq!(report.failed_byes, 0);
    println!("pbx: shut down, ending the call and refusing the other");
    drop(invite);

    // The phone saw both: a 503 for the second call, a BYE for the first.
    let unavailable = StatusCode::from_u16(503).unwrap();
    let (mut failed, mut ended) = (false, false);
    while !(failed && ended) {
        match next(&mut phone_events, Some).await {
            Event::AttemptEnded { attempt, result, .. }
                if attempt == ringing.id() =>
            {
                assert_eq!(
                    result,
                    AttemptResult::Failed(Error::RemoteFailure(unavailable))
                );
                failed = true;
            }
            Event::Ended { session: done, reason, .. } if done == session => {
                assert!(
                    matches!(reason, EndReason::RemoteBye { .. }),
                    "{reason:?}"
                );
                ended = true;
            }
            Event::AttemptEnded { attempt, result, .. } => {
                assert_eq!(attempt, answered.id());
                assert_eq!(result, AttemptResult::Answered);
            }
            _ => {}
        }
    }
    println!("phone: the second call got a 503, the first a BYE");

    let report =
        phone.shutdown(ShutdownMode::DrainExisting, LIMIT).await.unwrap();
    assert_eq!(report.outcome, ShutdownOutcome::Drained);
    assert_eq!(report.ended, 0);
    println!("phone: shut down");
    phone_driver.await.unwrap();
    pbx_driver.await.unwrap();
}

/// How long each shutdown may take: past every timer of RFC 3261's T1.
const LIMIT: Duration = Duration::from_secs(60);

const OFFER: &[u8] = b"v=0\r\no=phone 1 1 IN IP4 127.0.0.1\r\ns=-\r\n\
    c=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";
const ANSWER: &[u8] = b"v=0\r\no=pbx 1 1 IN IP4 127.0.0.1\r\ns=-\r\n\
    c=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40002 RTP/AVP 0\r\n";

fn sdp(body: &'static [u8]) -> Description {
    Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from_static(body),
    )
}

/// A UA on its own UDP endpoint on the loopback, named `user` in its Contact.
fn ua(timers: Timers, user: &str) -> (Ua, std::net::SocketAddr) {
    let (endpoint, incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .timers(timers)
        .bind()
        .unwrap();
    let address = endpoint.udp_addr().unwrap();
    let config =
        Config::new(&format!("sip:{user}@{address}")).unwrap().timers(timers);
    (attach(endpoint, incoming, config).unwrap(), address)
}

/// The next event for which `wanted` gives something.
async fn next<T>(
    events: &mut UaEvents,
    wanted: impl Fn(Event) -> Option<T>,
) -> T {
    loop {
        let event = timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("an event in time")
            .expect("the UA runs");
        // The queues here never fill, so a lost event is a failure.
        if let Event::Lagged { missed, .. } = event {
            panic!("{missed} events were lost");
        }
        if let Some(found) = wanted(event) {
            return found;
        }
    }
}

/// RFC 3261's timers, or those of the T1 that `--t1-ms` gives.
fn timers() -> Timers {
    let mut args = std::env::args().skip(1);
    let mut builder = Timers::builder();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--t1-ms" => {
                let ms = args.next().and_then(|ms| ms.parse().ok());
                let t1 = Duration::from_millis(ms.expect("--t1-ms takes ms"));
                builder = builder.t1(t1).t2(t1 * 8).t4(t1 * 10);
            }
            other => panic!("unknown argument {other}"),
        }
    }
    builder.build().unwrap()
}
