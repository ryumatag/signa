/*!
A call whose INVITE carries no offer, through signa-ua, on the loopback.

The caller sends an INVITE without an offer. The callee puts its offer in the
2xx, and the caller's answer goes in the ACK (RFC 3261 section 13.2.1). The UA
does not read session descriptions, so the caller gives it a provider that
does, an implementation of [`Negotiate`]. The UA asks it for the answer once
the 2xx comes, and sends the ACK with what it returns. If it returns nothing,
or not in time, the ACK goes without an answer, and the UA ends the dialog
with a BYE.

* The caller's UA has the provider in its configuration, and sends a plan
  made with [`InvitePlan::without_offer`].
* The callee sees an INVITE with no offer, and accepts with its offer.
* Both learn that the exchange completed from a `Negotiated` event, and each
  session's snapshot holds what the other side sent.

The example checks each step and fails otherwise. Pass `--t1-ms 50` for a
quicker run. The default is RFC 3261's T1 of 500 ms, and the shutdowns wait
for the transactions' timers, so the run takes about 35 s.
*/

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use signa::{
    HeaderValue,
    endpoint::{Endpoint, Incoming},
    transaction::Timers,
    ua::{
        Config, Description, Event, InvitePlan, Negotiate, NegotiationState,
        Offer, ShutdownMode, ShutdownOutcome, Ua, UaEvents, attach,
    },
};
use tokio::time::timeout;

/// The caller's SDP component, as far as the example needs one. It answers
/// any offer with the same description, and keeps the offers for `main` to
/// check, since a panic here would only read as no answer.
///
/// A real one answers an offer without a session, which `Offer::session`
/// returns for a dialog the UA ends, with an answer that rejects it.
#[derive(Clone, Default)]
struct Answerer {
    offers: Arc<Mutex<Vec<Bytes>>>,
}

impl Negotiate for Answerer {
    async fn answer(&self, offer: &Offer) -> Option<Description> {
        let body = offer.description().body().clone();
        self.offers.lock().unwrap().push(body);
        Some(sdp(ANSWER))
    }
}

#[tokio::main]
async fn main() {
    let timers = timers();
    let answerer = Answerer::default();
    let (endpoint, incoming, caller_address) = bind(timers);
    let config = Config::new(&format!("sip:caller@{caller_address}"))
        .unwrap()
        .timers(timers)
        .negotiator(answerer.clone());
    let Ua { handle: caller, events: mut caller_events, driver } =
        attach(endpoint, incoming, config).unwrap();
    let caller_driver = tokio::spawn(driver);
    let (endpoint, incoming, callee_address) = bind(timers);
    let config = Config::new(&format!("sip:callee@{callee_address}"))
        .unwrap()
        .timers(timers);
    let Ua { handle: callee, events: mut callee_events, driver } =
        attach(endpoint, incoming, config).unwrap();
    let callee_driver = tokio::spawn(driver);

    // The callee's application: it gets no offer, so its 2xx makes one.
    let answering = tokio::spawn(async move {
        let invite = next(&mut callee_events, |event| match event {
            Event::Invite(invite) => Some(invite),
            _ => None,
        })
        .await;
        assert!(invite.offer().is_none());
        let session = invite.try_accept(sdp(OFFER)).unwrap().await.unwrap();
        next(&mut callee_events, |event| match event {
            Event::Negotiated { session: done, .. } if done == session => {
                Some(())
            }
            _ => None,
        })
        .await;
        println!("callee: the ACK brought the answer");
        (callee_events, session)
    });

    let plan = InvitePlan::without_offer(
        format!("sip:callee@{callee_address}").parse().unwrap(),
        "sip:caller@127.0.0.1".parse().unwrap(),
    );
    caller.try_invite(plan).unwrap().await.unwrap();
    let session = next(&mut caller_events, |event| match event {
        Event::Negotiated { session, .. } => Some(session),
        _ => None,
    })
    .await;
    let snapshot = caller.snapshot(&session).await.unwrap().unwrap();
    assert_eq!(snapshot.negotiation, NegotiationState::Settled);
    let offer = snapshot.remote_description.expect("the 2xx carried one");
    assert_eq!(offer.body(), &Bytes::from_static(OFFER));
    let offers = answerer.offers.lock().unwrap().clone();
    assert_eq!(offers, [Bytes::from_static(OFFER)]);
    println!("caller: answered the offer of the 2xx in the ACK");

    let (_callee_events, callee_session) = answering.await.unwrap();
    let snapshot = callee.snapshot(&callee_session).await.unwrap().unwrap();
    let answer = snapshot.remote_description.expect("the ACK carried one");
    assert_eq!(answer.body(), &Bytes::from_static(ANSWER));

    caller.try_terminate(&session).unwrap().await.unwrap();
    println!("caller: hung up");
    for (name, handle) in [("caller", &caller), ("callee", &callee)] {
        let report =
            handle.shutdown(ShutdownMode::DrainExisting, LIMIT).await.unwrap();
        assert_eq!(report.outcome, ShutdownOutcome::Drained, "{name}");
        println!("{name}: shut down");
    }
    caller_driver.await.unwrap();
    callee_driver.await.unwrap();
}

/// How long each shutdown may take: past every timer of RFC 3261's T1.
const LIMIT: Duration = Duration::from_secs(60);

const OFFER: &[u8] = b"v=0\r\no=callee 1 1 IN IP4 127.0.0.1\r\ns=-\r\n\
    c=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40002 RTP/AVP 0\r\n";
const ANSWER: &[u8] = b"v=0\r\no=caller 1 1 IN IP4 127.0.0.1\r\ns=-\r\n\
    c=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";

fn sdp(body: &'static [u8]) -> Description {
    Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from_static(body),
    )
}

/// A UDP endpoint on the loopback, and its address.
fn bind(timers: Timers) -> (Endpoint, Incoming, std::net::SocketAddr) {
    let (endpoint, incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .timers(timers)
        .bind()
        .unwrap();
    let address = endpoint.udp_addr().unwrap();
    (endpoint, incoming, address)
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
