/*!
Two UAs call each other through signa-ua, on the loopback.

The callee rings and answers, then hangs up, and both shut down. Each side
does what an application does with a UA:

* Attach a UA to a signa endpoint, and spawn its driver.
* The caller sends an INVITE with an offer, and learns of the session the
  2xx confirms from its events. The UA sends the ACK.
* The callee takes the INVITE from its events, sends a 180, and accepts with
  its answer. The UA retransmits the 2xx until the ACK.
* The callee ends the session. Its UA holds the BYE until the ACK has come
  (RFC 3261 section 15). The caller learns of the BYE from its events, and
  its UA answers it.
* Each shuts its UA down. The UA finishes what is under way, then shuts the
  endpoint down, within one deadline.

The example checks each step and fails otherwise. Pass `--t1-ms 50` for a
quicker run. The default is RFC 3261's T1 of 500 ms, and the shutdowns wait
for the transactions' timers, so the run takes about 35 s.
*/

use std::time::Duration;

use bytes::Bytes;
use signa::{
    HeaderValue, StatusCode,
    endpoint::Endpoint,
    transaction::Timers,
    ua::{
        Config, Description, EndReason, Event, InvitePlan, SessionPhase,
        ShutdownMode, ShutdownOutcome, Ua, UaEvents, attach,
    },
};
use tokio::{sync::oneshot, time::timeout};

#[tokio::main]
async fn main() {
    let timers = timers();
    let (caller, _) = ua(timers, "caller");
    let (callee, callee_address) = ua(timers, "callee");
    let Ua { handle: caller, events: mut caller_events, driver } = caller;
    let caller_driver = tokio::spawn(driver);
    let Ua { handle: callee, events: mut callee_events, driver } = callee;
    let callee_driver = tokio::spawn(driver);

    // The callee's application: ring, answer, and hang up once the caller
    // has seen the call.
    let (seen, in_call) = oneshot::channel();
    let answering = tokio::spawn(async move {
        let invite = next(&mut callee_events, |event| match event {
            Event::Invite(invite) => Some(invite),
            _ => None,
        })
        .await;
        let offer = invite.offer().expect("the INVITE carries an offer");
        assert_eq!(offer.body(), &Bytes::from_static(OFFER));
        let ringing = StatusCode::from_u16(180).unwrap();
        invite.try_provisional(ringing).unwrap().await.unwrap();
        let session = invite.try_accept(sdp(ANSWER)).unwrap().await.unwrap();
        println!("callee: answered");

        in_call.await.unwrap();
        callee.try_terminate(&session).unwrap().await.unwrap();
        // Had no ACK come, the UA would say so first, and send the BYE at
        // 64 T1.
        let reason = next(&mut callee_events, |event| match event {
            Event::AckTimeout { .. } => panic!("no ACK came"),
            Event::Ended { session: ended, reason, .. }
                if ended == session =>
            {
                Some(reason)
            }
            _ => None,
        })
        .await;
        assert_eq!(reason, EndReason::LocalBye);
        println!("callee: hung up after the ACK");
        callee
    });

    // The caller's application: call, then hang up.
    let plan = InvitePlan::new(
        format!("sip:callee@{callee_address}").parse().unwrap(),
        "sip:caller@127.0.0.1".parse().unwrap(),
        sdp(OFFER),
    );
    caller.try_invite(plan).unwrap().await.unwrap();
    let session = next(&mut caller_events, |event| match event {
        Event::Confirmed { session, .. } => Some(session),
        _ => None,
    })
    .await;
    let snapshot = caller.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.phase, SessionPhase::Established);
    let answer = snapshot.remote_description.expect("the 2xx carried one");
    assert_eq!(answer.body(), &Bytes::from_static(ANSWER));
    println!("caller: in a call");
    seen.send(()).unwrap();

    let reason = next(&mut caller_events, |event| match event {
        Event::Ended { session: ended, reason, .. } if ended == session => {
            Some(reason)
        }
        _ => None,
    })
    .await;
    assert!(matches!(reason, EndReason::RemoteBye { .. }), "{reason:?}");
    println!("caller: the callee hung up");
    let callee = answering.await.unwrap();

    for (name, handle) in [("caller", &caller), ("callee", &callee)] {
        let shutdown = handle.shutdown(ShutdownMode::DrainExisting, LIMIT);
        let report = shutdown.await.unwrap();
        assert_eq!(report.outcome, ShutdownOutcome::Drained, "{name}");
        println!("{name}: shut down");
    }
    caller_driver.await.unwrap();
    callee_driver.await.unwrap();
}

/// How long each shutdown may take: past every timer of RFC 3261's T1.
const LIMIT: Duration = Duration::from_secs(60);

const OFFER: &[u8] = b"v=0\r\no=caller 1 1 IN IP4 127.0.0.1\r\ns=-\r\n\
    c=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";
const ANSWER: &[u8] = b"v=0\r\no=callee 1 1 IN IP4 127.0.0.1\r\ns=-\r\n\
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
