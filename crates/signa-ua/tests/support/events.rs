/*!
Waiting for the events a test expects of a UA.
*/

use std::time::Duration;

use signa_ua::{
    AttemptResult, Event, IncomingInvite, ShutdownReport, UaEvents,
};
use tokio::time::timeout;

use crate::support::WAIT;

pub(crate) async fn invite(events: &mut UaEvents) -> signa_ua::IncomingInvite {
    loop {
        match timeout(WAIT, events.recv()).await.unwrap().unwrap() {
            Event::Invite(invite) => return invite,
            _ => continue,
        }
    }
}

/// Says whether an INVITE reaches the application within `wait`.
pub(crate) async fn invite_within(
    events: &mut UaEvents,
    wait: Duration,
) -> bool {
    let next = async {
        loop {
            if let Event::Invite(_) = events.recv().await.unwrap() {
                return;
            }
        }
    };
    timeout(wait, next).await.is_ok()
}

/// Receives events until the attempt ends, and returns what it came to.
pub(crate) async fn attempt_end(
    events: &mut UaEvents,
) -> (AttemptResult, bool) {
    loop {
        if let Event::AttemptEnded { result, complete, .. } =
            timeout(WAIT, events.recv()).await.unwrap().unwrap()
        {
            return (result, complete);
        }
    }
}

/// Receives events until `pick` takes one.
pub(crate) async fn event<T>(
    events: &mut UaEvents,
    mut pick: impl FnMut(Event) -> Option<T>,
) -> T {
    loop {
        let next = timeout(WAIT, events.recv()).await.unwrap().unwrap();
        if let Some(found) = pick(next) {
            return found;
        }
    }
}

/// Receives events until a re-INVITE comes.
pub(crate) async fn reinvite(events: &mut UaEvents) -> IncomingInvite {
    event(events, |event| match event {
        Event::Reinvite(invite) => Some(invite),
        _ => None,
    })
    .await
}

pub(crate) async fn reinvite_event(events: &mut UaEvents) -> IncomingInvite {
    event(events, |event| match event {
        Event::Reinvite(invite) => Some(invite),
        _ => None,
    })
    .await
}

/// Waits for the report of a shutdown, which must come within `wait`.
pub(crate) async fn report_within(
    shutdown: signa_ua::UaShutdown,
    wait: Duration,
) -> ShutdownReport {
    timeout(wait, shutdown).await.expect("a report in time").unwrap()
}
