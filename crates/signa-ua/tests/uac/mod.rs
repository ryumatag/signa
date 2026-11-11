/*!
The initial INVITE the UA sends (RFC 3261 sections 8.1 and 13.2).
*/

mod attempt;
mod fork;
mod offer;

use signa_ua::{AttemptResult, Event, Session, UaEvents};
use tokio::time::timeout;

use crate::support::WAIT;

/// What the events of an attempt said by its end: the sessions each 2xx
/// confirmed, in order, and what [`Event::AttemptEnded`] reported.
struct Ending {
    confirmed: Vec<Session>,
    result: AttemptResult,
    complete: bool,
    degraded: bool,
    sessions: Vec<Session>,
}

/// Receives events until the attempt ends, keeping the sessions the 2xx
/// responses confirmed.
async fn ending(events: &mut UaEvents) -> Ending {
    let mut confirmed = Vec::new();
    loop {
        match timeout(WAIT, events.recv()).await.unwrap().unwrap() {
            Event::Confirmed { session, .. } => confirmed.push(session),
            Event::AttemptEnded {
                result,
                complete,
                degraded,
                sessions,
                ..
            } => {
                return Ending {
                    confirmed,
                    result,
                    complete,
                    degraded,
                    sessions,
                };
            }
            _ => {}
        }
    }
}
