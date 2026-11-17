/*!
The bounded dispatcher, with its ordinary and control lanes.
*/

use std::{collections::VecDeque, fmt, future::poll_fn};

use signa_core::{
    endpoint::{
        Incoming, IncomingEvent, ReceivedAck, ReceivedRequest, Responder,
        ServerRequest, ServerTransactionId,
    },
    message::header::Tag,
};
use tokio::task::JoinSet;
use tower::Service;

use crate::tower::{adapter::Exchange, reply};

/// What the control lane carries. Only a matched CANCEL has a responder.
pub(crate) enum Control<R> {
    Cancel {
        exchange: Exchange<R>,
        target: ServerTransactionId,
    },
    Ack(ReceivedAck),
    UnmatchedCancel(ReceivedRequest),
    // The control service here drops an untracked request unread, but the
    // dispatcher hands it over all the same.
    #[expect(dead_code)]
    Untracked(ReceivedRequest),
}

/// The bounds `dispatch` keeps.
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    /// Ordinary handler futures running at once.
    pub(crate) handlers: usize,
    /// Ordinary requests received but not yet called.
    pub(crate) queued: usize,
    /// The same two bounds for the control lane.
    pub(crate) control_handlers: usize,
    pub(crate) control_queued: usize,
    /// 503s for ordinary overflow in flight at once.
    pub(crate) rejections: usize,
}

/// What `dispatch` saw, for the tests to check.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    pub(crate) most_handlers: usize,
    pub(crate) most_queued: usize,
    pub(crate) rejected: usize,
    pub(crate) dropped_control: usize,
    pub(crate) handler_errors: usize,
}

/// Runs both lanes until `incoming` ends and every handler has finished.
///
/// One `select!` loop receives events, polls readiness and reaps finished
/// handlers, so nothing in it waits for a lane that has no room or a service
/// that is not ready. Readiness is polled only when a call is queued and the
/// lane has room, and the call follows on the same instance at once.
pub(crate) async fn dispatch<S, C>(
    mut incoming: Incoming,
    mut requests: S,
    mut control: C,
    limits: Limits,
) -> Stats
where
    S: Service<Exchange<Responder>, Response = ()>,
    S::Future: Send + 'static,
    S::Error: fmt::Debug + Send + 'static,
    C: Service<Control<Responder>, Response = ()>,
    C::Future: Send + 'static,
    C::Error: fmt::Debug + Send + 'static,
{
    let mut stats = Stats::default();
    let mut ordinary: VecDeque<Exchange<Responder>> = VecDeque::new();
    let mut controls: VecDeque<Control<Responder>> = VecDeque::new();
    let mut handlers = JoinSet::new();
    let mut control_handlers = JoinSet::new();
    let mut rejections = JoinSet::new();
    let mut open = true;

    loop {
        let idle = ordinary.is_empty()
            && controls.is_empty()
            && handlers.is_empty()
            && control_handlers.is_empty()
            && rejections.is_empty();
        if !open && idle {
            return stats;
        }

        let control_room = !controls.is_empty()
            && control_handlers.len() < limits.control_handlers;
        let ordinary_room =
            !ordinary.is_empty() && handlers.len() < limits.handlers;

        tokio::select! {
            biased;

            Some(done) = handlers.join_next(), if !handlers.is_empty() => {
                match done {
                    Ok(Ok(())) => {}
                    // The error is the handler's. signa's drop policy has
                    // already run for any responder it dropped.
                    Ok(Err(_)) | Err(_) => stats.handler_errors += 1,
                }
            }
            Some(_) = control_handlers.join_next(),
                if !control_handlers.is_empty() => {}
            Some(_) = rejections.join_next(), if !rejections.is_empty() => {}

            ready = poll_fn(|cx| control.poll_ready(cx)), if control_room => {
                ready.expect("the control service does not fail");
                let event = controls.pop_front().expect("checked above");
                control_handlers.spawn(control.call(event));
            }
            ready = poll_fn(|cx| requests.poll_ready(cx)), if ordinary_room => {
                ready.expect("the request service does not fail");
                let exchange = ordinary.pop_front().expect("checked above");
                handlers.spawn(requests.call(exchange));
                stats.most_handlers = stats.most_handlers.max(handlers.len());
            }

            event = incoming.recv(), if open => match event {
                None => open = false,
                Some(IncomingEvent::Request(request)) => {
                    let exchange = Exchange::new(request);
                    if ordinary.len() < limits.queued {
                        ordinary.push_back(exchange);
                        stats.most_queued =
                            stats.most_queued.max(ordinary.len());
                    } else {
                        stats.rejected += 1;
                        if rejections.len() < limits.rejections {
                            rejections.spawn(reject(exchange));
                        }
                        // Otherwise the responder drops here, and signa
                        // sends its 500.
                    }
                }
                Some(event) => {
                    let event = match event {
                        IncomingEvent::Cancel(cancel) => Control::Cancel {
                            target: cancel.target,
                            exchange: Exchange::new(ServerRequest {
                                request: cancel.request,
                                received: cancel.received,
                                transaction: cancel.transaction,
                            }),
                        },
                        IncomingEvent::Ack(ack) => Control::Ack(ack),
                        IncomingEvent::UnmatchedCancel(cancel) => {
                            Control::UnmatchedCancel(cancel)
                        }
                        IncomingEvent::Untracked(request) => {
                            Control::Untracked(request)
                        }
                        _ => {
                            stats.dropped_control += 1;
                            continue;
                        }
                    };
                    if controls.len() < limits.control_queued {
                        controls.push_back(event);
                    } else {
                        // A dropped ACK gets nothing, and a dropped CANCEL
                        // responder gets signa's 500.
                        stats.dropped_control += 1;
                    }
                }
            },
        }
    }
}

async fn reject(exchange: Exchange<Responder>) {
    let unavailable = reply(&exchange.request, 503, &Tag::random());
    let _ = exchange.responder.respond(unavailable).await;
}
