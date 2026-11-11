/*!
Forks of one INVITE. Each 2xx is a session of its own with an ACK of its own
(RFC 3261 section 13.2.2.4), within the limits on what the UA keeps of them.
*/

use std::time::Duration;

use signa_ua::AttemptResult;
use tokio::time::timeout;

use crate::{
    support::{
        config,
        message::{answer, branch, header, ok_to, plan_to},
        peer::Peer,
        start_fast, start_fast_with,
    },
    uac::ending,
};

/// A forking proxy has two callees answer the INVITE, here played by one
/// socket with two tags. Each 2xx is a session of its own, and gets an ACK
/// of its own with its tag and a branch of its own (RFC 3261 section
/// 13.2.2.4). The attempt lists both while it runs, and ends complete.
#[tokio::test]
async fn two_forks_on_the_wire_get_an_ack_each() {
    let (mut ua, _, _) = start_fast();
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let contact = format!("sip:peer@{to}");

    let attempt =
        ua.handle.try_invite(plan_to(&to, "forks")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "200", "bob", &contact), from).await;
    let (bob, _) = peer.recv_starting("ACK").await;
    peer.send(&answer(&request, "200", "carol", &contact), from).await;
    let (carol, _) = peer.recv_starting("ACK").await;
    let snapshot =
        ua.handle.attempt_snapshot(&attempt).await.unwrap().unwrap();

    assert!(header(&bob, "To")[0].ends_with(";tag=bob"));
    assert!(header(&carol, "To")[0].ends_with(";tag=carol"));
    assert_ne!(branch(&bob), branch(&carol));
    assert_eq!(header(&bob, "CSeq"), header(&carol, "CSeq"));
    assert_eq!(snapshot.sessions.len(), 2);
    let ending = ending(&mut ua.events).await;
    assert_eq!(ending.confirmed, snapshot.sessions);
    assert_eq!(ending.sessions, snapshot.sessions);
    assert_eq!(ending.result, AttemptResult::Answered);
    assert!(ending.complete && !ending.degraded);
}

/// A fork beyond the attempt's limit gets its ACK and then a BYE, the
/// request after the INVITE in its dialog (RFC 3261 sections 13.2.2.4 and
/// 15.1.1), and is no session. A copy of its 2xx that comes after the BYE
/// still gets the ACK, the same one, and no second BYE. The attempt ends
/// incomplete, since it could not report that fork.
#[tokio::test]
async fn bye_then_retransmitted_2xx_still_gets_ack() {
    let (mut ua, _, _) = start_fast_with(config().max_forks(1));
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let contact = format!("sip:peer@{to}");

    ua.handle.try_invite(plan_to(&to, "beyond")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    peer.send(&answer(&request, "200", "kept", &contact), from).await;
    peer.recv_starting("ACK").await;
    let ended = answer(&request, "200", "ended", &contact);
    peer.send(&ended, from).await;
    let (ack, _) = peer.recv_starting("ACK").await;
    let (bye, bye_from) = peer.recv_starting("BYE").await;
    peer.send(&ok_to(&bye), bye_from).await;
    peer.send(&ended, from).await;
    let (again, _) = peer.recv_starting("ACK").await;
    peer.quiet("BYE", Duration::from_millis(300)).await;

    assert!(header(&ack, "To")[0].ends_with(";tag=ended"));
    assert_eq!(again, ack);
    assert_eq!(header(&bye, "To"), header(&ack, "To"));
    assert_eq!(header(&bye, "Call-ID"), header(&request, "Call-ID"));
    let number: u32 = header(&request, "CSeq")[0]
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(header(&bye, "CSeq"), [format!("{} BYE", number + 1)]);
    assert!(bye.starts_with(&format!("BYE {contact} ")));
    let ending = ending(&mut ua.events).await;
    assert_eq!(ending.confirmed.len(), 1);
    assert_eq!(ending.result, AttemptResult::Answered);
    assert!(!ending.complete && !ending.degraded);
}

/// A flood of forks stays within the limits. One fork is a session and
/// one is acknowledged and ended, and the third gets nothing, which the
/// attempt reports as degraded at its end.
#[tokio::test]
async fn a_fork_flood_on_the_wire_stays_within_its_limits() {
    let (mut ua, _, _) =
        start_fast_with(config().max_forks(1).max_cleanups(1));
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let contact = format!("sip:peer@{to}");

    ua.handle.try_invite(plan_to(&to, "flood")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    for tag in ["first", "second", "third"] {
        peer.send(&answer(&request, "200", tag, &contact), from).await;
    }
    let mut tags = Vec::new();
    let _ = timeout(Duration::from_millis(500), async {
        loop {
            let (message, at) = peer.recv().await;
            if message.starts_with("ACK") {
                tags.push(header(&message, "To")[0].to_owned());
            } else if message.starts_with("BYE") {
                peer.send(&ok_to(&message), at).await;
            }
        }
    })
    .await;

    assert_eq!(tags.len(), 2, "{tags:?}");
    assert!(tags.iter().all(|to| !to.ends_with(";tag=third")));
    let ending = ending(&mut ua.events).await;
    assert_eq!(ending.confirmed.len(), 1);
    assert!(!ending.complete && ending.degraded);
}

/// The notifications of a fork can be lost to a full event queue, and the
/// attempt can end before the application asks for its snapshot. Its end,
/// which is never dropped, still lists every session it formed, so none is
/// lost to the application.
#[tokio::test]
async fn forks_whose_notifications_were_lost_are_listed_at_the_end() {
    let config = config().event_capacity(1).max_attempts(1);
    let (mut ua, _, _) = start_fast_with(config);
    tokio::spawn(ua.driver);
    let peer = Peer::new().await;
    let to = peer.address().to_string();
    let contact = format!("sip:peer@{to}");

    ua.handle.try_invite(plan_to(&to, "lost")).unwrap().await.unwrap();
    let (request, from) = peer.recv_starting("INVITE").await;
    for tag in ["first", "second"] {
        peer.send(&answer(&request, "200", tag, &contact), from).await;
        peer.recv_starting("ACK").await;
    }
    // Timer M, 64 T1 after the first 2xx, ends the attempt meanwhile.
    tokio::time::sleep(Duration::from_millis(1600)).await;

    let ending = ending(&mut ua.events).await;
    assert!(ending.confirmed.len() < 2, "a notification was dropped");
    assert_eq!(ending.sessions.len(), 2);
    for session in &ending.sessions {
        let snapshot = ua.handle.snapshot(session).await.unwrap();
        assert!(snapshot.is_some(), "{session:?} is still up");
    }
}
