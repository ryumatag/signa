/*!
A minimal adapter from a UA's events to a Tower service, built on signa-ua's
public API alone, as a crate on top of it would be.

[`serve`] hands each [`IncomingInvite`], initial or re-INVITE, to a
`Service<IncomingInvite, Response = ()>`. The INVITE is the request. It
carries what a handler reads, the request, its flow, the session of a
re-INVITE and the offer, and with them the authority to decide it, so the
adapter adds no envelope of its own. The other events go to the application
as they are.

The future of a call is the handler's work, and its end is only the
handler's. It is not the final response, the ACK or the end of a dialog,
which the UA keeps apart from it. Dropping it, as a Tower timeout does, does
nothing in SIP either. An INVITE dropped undecided with it gets the UA's 500,
and nothing is cancelled.

How the adapter treats readiness is my own policy, not anything RFC 3261
asks:

* It polls the service ready before it takes the next event, and calls that
  instance as soon as an INVITE comes. So it never holds an INVITE the
  service cannot take. While the service is not ready, the INVITEs wait in
  the UA's event queue, and the UA refuses one beyond it with a 503. The
  other events wait there too, behind them, and the UA counts those it drops
  as a lag. A handler that holds an INVITE meanwhile learns of its CANCEL
  from its decision, which finds the final taken.
* A readiness error says that the service cannot serve any more (the
  contract of `Service::poll_ready`). The adapter drops it and the events.
  The INVITEs still queued then get the UA's 500 for a dropped decision, and
  later ones its 503 for an INVITE nobody can decide.
* Once the UA has stopped, which the end of its driver says, the adapter
  aborts the handlers still running, since nothing they decide reaches the
  wire any more, and returns.

Each handler runs as a task of the adapter's `JoinSet`, so the adapter knows
of every one until it ends. The adapter never shuts the UA or its endpoint
down. The application does that with `UaHandle::shutdown`, and the UA's
drain waits for the decisions the handlers hold. A shutdown of the endpoint
from here would only wait for its deadline, since the UA holds a work guard
while it has work.
*/

use std::{fmt, future::poll_fn};

use signa_ua::{Event, IncomingInvite, UaEvents};
use tokio::{
    sync::mpsc,
    task::{JoinError, JoinSet},
};
use tower::Service;

/// What became of the calls of one [`serve`].
#[derive(Debug, Default)]
pub(super) struct Served {
    /// Calls of the service, one for each INVITE.
    pub(super) calls: usize,
    /// Handlers whose future ended with `Ok`.
    pub(super) completed: usize,
    /// Handlers whose future ended with an error, such as a Tower timeout.
    pub(super) failed: usize,
    /// Handlers that panicked.
    pub(super) panicked: usize,
    /// Handlers still running when the UA stopped.
    pub(super) aborted: usize,
    /// The readiness error the adapter gave the service up at.
    pub(super) readiness: Option<String>,
}

impl Served {
    fn count<E>(&mut self, ended: Result<Result<(), E>, JoinError>) {
        match ended {
            Ok(Ok(())) => self.completed += 1,
            Ok(Err(_)) => self.failed += 1,
            Err(error) if error.is_panic() => self.panicked += 1,
            Err(_) => self.aborted += 1,
        }
    }
}

/// Hands the INVITEs of `events` to `service`, and every other event to
/// `notifications`, until `stopped`, which resolves once the UA's driver has
/// returned.
pub(super) async fn serve<S>(
    mut events: UaEvents,
    mut service: S,
    stopped: impl Future,
    notifications: mpsc::UnboundedSender<Event>,
) -> Served
where
    S: Service<IncomingInvite, Response = ()>,
    S::Future: Send + 'static,
    S::Error: fmt::Debug + Send + 'static,
{
    let mut served = Served::default();
    let mut handlers = JoinSet::new();
    tokio::pin!(stopped);

    loop {
        // Readiness comes first, so that no INVITE waits here for it. The
        // handlers that end meanwhile give their room back.
        let ready = tokio::select! {
            biased;
            _ = &mut stopped => break,
            Some(ended) = handlers.join_next() => {
                served.count(ended);
                continue;
            }
            ready = poll_fn(|cx| service.poll_ready(cx)) => ready,
        };
        if let Err(error) = ready {
            served.readiness = Some(format!("{error:?}"));
            drop((service, events));
            // The handlers already called go on until they end or the UA
            // stops.
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    ended = handlers.join_next() => match ended {
                        Some(ended) => served.count(ended),
                        None => return served,
                    },
                }
            }
            break;
        }

        // The service is ready, and this instance takes the next INVITE.
        let event = tokio::select! {
            biased;
            _ = &mut stopped => break,
            Some(ended) = handlers.join_next() => {
                served.count(ended);
                continue;
            }
            event = events.recv() => event,
        };
        match event {
            Some(Event::Invite(invite) | Event::Reinvite(invite)) => {
                served.calls += 1;
                handlers.spawn(service.call(invite));
            }
            Some(other) => {
                // The application may have stopped listening.
                let _ = notifications.send(other);
            }
            None => break,
        }
    }

    // The UA has stopped, so no handler can decide anything any more.
    handlers.abort_all();
    while let Some(ended) = handlers.join_next().await {
        served.count(ended);
    }
    served
}
