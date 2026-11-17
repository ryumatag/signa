/*!
A transport error on a response leaves its server transaction in its state
(RFC 6026 section 8.8).
*/

use std::time::Duration;

use bytes::Bytes;
use signa_core::{
    Response,
    endpoint::{Endpoint, ServerEvent},
    message::header::Tag,
    transaction::Timers,
};
use tokio::time::timeout;

use crate::{
    datagram::{
        bind, datagram, invite, options, status,
        wire::{Wire, Writes},
    },
    support::request,
};

/// When a write of a server transaction fails.
#[derive(Clone, Copy, Debug)]
enum Failure {
    /// The wire refuses it when it is offered.
    Refused,
    /// The wire holds it, then refuses it.
    HeldThenRefused,
    /// The wire takes it and reports that writing it failed.
    Failed,
}

// RFC 6026 section 8.8 replaces the paragraph of RFC 3261 section 17.2.4 that
// ended a server transaction whose response could not be sent. It now
// "SHOULD inform the TU that a failure has occurred, and MUST remain in the
// current state". However the final fails, and whether or not the TU
// observes, an INVITE and a non-INVITE stay in Completed. A retransmission
// of the request is absorbed rather than reaching the TU again, and its
// cached final goes out once the wire takes writes again.
#[tokio::test]
async fn a_failed_final_leaves_the_server_transaction_in_its_state() {
    for failure in
        [Failure::Refused, Failure::HeldThenRefused, Failure::Failed]
    {
        for observed in [true, false] {
            for is_invite in [false, true] {
                let case = format!("{failure:?} {observed} {is_invite}");
                let branch = case.replace(' ', "-").to_lowercase();
                let text =
                    if is_invite { invite(&branch) } else { options(&branch) };
                let code = if is_invite { 486 } else { 200 };
                let wire = Wire::default();
                let (_endpoint, mut incoming) = bind(&wire);

                wire.deliver(datagram(text.clone()));
                let request = request(&mut incoming).await;
                if is_invite {
                    wire.sent(1).await; // The automatic 100.
                }
                let (responder, events) = request.transaction.into_parts();
                let mut events = observed.then_some(events);
                let response = Response::reply_to(&request.request)
                    .status(code)
                    .to_tag(Tag::random())
                    .body(Bytes::new())
                    .unwrap();
                let accepted = wire.count();
                wire.writes(match failure {
                    Failure::Refused => Writes::Reject,
                    Failure::HeldThenRefused => Writes::Hold,
                    Failure::Failed => Writes::Fail,
                });
                responder.respond(response).await.unwrap();
                // The write has failed once the wire has refused it or taken
                // it, since the wire reports a failure as it takes the write.
                if let Failure::HeldThenRefused = failure {
                    wire.until(|state| state.submit.is_some()).await;
                    wire.writes(Writes::Reject);
                }
                match failure {
                    Failure::Refused | Failure::HeldThenRefused => {
                        wire.until(|state| state.refused >= 1).await;
                    }
                    Failure::Failed => {
                        wire.sent(accepted + 1).await;
                    }
                }

                if let Some(events) = &mut events {
                    let event = timeout(Duration::from_secs(2), events.next())
                        .await
                        .unwrap();
                    assert!(
                        matches!(
                            event,
                            Some(ServerEvent::TransportFailure {
                                operation: Some(_),
                                ..
                            })
                        ),
                        "{case}: {event:?}"
                    );
                }

                wire.deliver(datagram(text.clone()));
                if let Some(events) = &mut events {
                    let event = timeout(Duration::from_secs(2), events.next())
                        .await
                        .unwrap();
                    assert!(
                        matches!(
                            event,
                            Some(ServerEvent::TransportFailure {
                                operation: None,
                                ..
                            })
                        ),
                        "{case}: {event:?}"
                    );
                }
                assert!(
                    timeout(Duration::from_millis(50), incoming.recv())
                        .await
                        .is_err(),
                    "{case}: the retransmission reached the TU"
                );

                wire.writes(Writes::Complete);
                let before = wire.count();
                wire.deliver(datagram(text));
                let sent = wire.sent(before + 1).await;
                assert_eq!(status(&sent[before]), code, "{case}");
            }
        }
    }
}

// A failed provisional leaves a server transaction in Proceeding too (RFC 6026
// section 8.8). For an INVITE it is the TU's 180. For a non-INVITE it is the
// automatic 100, which a non-INVITE over UDP gets once the client's Timer E
// would reach T2 (RFC 4320 section 4.1), and whose failure used to end it. A
// retransmission then gets the provisional again, and the final still goes.
#[tokio::test]
async fn a_failed_provisional_leaves_the_server_transaction_in_proceeding() {
    let timers = Timers::builder()
        .t1(Duration::from_millis(5))
        .t2(Duration::from_millis(20))
        .build()
        .unwrap();
    for failure in
        [Failure::Refused, Failure::HeldThenRefused, Failure::Failed]
    {
        for is_invite in [false, true] {
            let case = format!("{failure:?} {is_invite}");
            let branch = case.replace(' ', "-").to_lowercase() + "-1xx";
            let text =
                if is_invite { invite(&branch) } else { options(&branch) };
            let wire = Wire::default();
            let (_endpoint, mut incoming) = Endpoint::builder()
                .udp_io(wire.clone())
                .timers(timers)
                .bind()
                .unwrap();
            let failing = match failure {
                Failure::Refused => Writes::Reject,
                Failure::HeldThenRefused => Writes::Hold,
                Failure::Failed => Writes::Fail,
            };

            if !is_invite {
                wire.writes(failing);
            }
            wire.deliver(datagram(text.clone()));
            let request = request(&mut incoming).await;
            let (responder, mut events) = request.transaction.into_parts();
            let tag = Tag::random();
            if is_invite {
                wire.sent(1).await; // The automatic 100.
                wire.writes(failing);
                let ringing = Response::reply_to(&request.request)
                    .status(180)
                    .to_tag(tag.clone())
                    .body(Bytes::new())
                    .unwrap();
                responder.respond(ringing).await.unwrap();
            }
            if let Failure::HeldThenRefused = failure {
                wire.until(|state| state.submit.is_some()).await;
                wire.writes(Writes::Reject);
            }
            let event =
                timeout(Duration::from_secs(2), events.next()).await.unwrap();
            assert!(
                matches!(
                    event,
                    Some(ServerEvent::TransportFailure { operation, .. })
                        if operation.is_some() == is_invite
                ),
                "{case}: {event:?}"
            );

            wire.writes(Writes::Complete);
            let before = wire.count();
            wire.deliver(datagram(text));
            let resent = &wire.sent(before + 1).await[before];
            let provisional = if is_invite { 180 } else { 100 };
            assert_eq!(status(resent), provisional, "{case}");

            let code = if is_invite { 486 } else { 200 };
            let response = Response::reply_to(&request.request)
                .status(code)
                .to_tag(tag.clone())
                .body(Bytes::new())
                .unwrap();
            responder.respond(response).await.unwrap();
            let sent = wire.sent(before + 2).await;
            assert_eq!(status(&sent[before + 1]), code, "{case}");
        }
    }
}
