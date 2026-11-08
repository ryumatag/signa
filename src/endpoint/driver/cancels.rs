/*!
CANCEL in the driver, as a separate non-INVITE transaction
([RFC 3261 section 9]).

On the client side, each INVITE has one cancellation intent and a CANCEL
transaction reserved at admission. The intent waits for a provisional response,
and the CANCEL then copies the INVITE's identity, routing and top Via. On the
server side, a new CANCEL is matched to its target and handed to the TU with
its own transaction. What the CANCEL means for the target is the TU's decision.

[RFC 3261 section 9]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9
*/

use std::{io, mem, sync::Arc, time::Instant};

use bytes::Bytes;
use tokio::sync::oneshot;

use super::{
    identity_bytes, now, send_client, send_on, Cancel, CancelStart,
    ClientEntry, ClientMachine, Driver, Key, Link, Pending, ServerMachine,
    SERVICE_UNAVAILABLE,
};
use crate::{
    endpoint::{
        admission::request_bytes,
        client::{CancelError, CancelOutcome, Intent, Reserved},
        error::Error,
        server::{self, IncomingCancel, IncomingEvent},
        table::Id,
    },
    message::{header::VIA, request::Request},
    transaction::{
        key::{ClientKey, ServerKey},
        non_invite::{ClientTransaction, ServerTransaction},
    },
    transport::Flow,
};

impl Driver {
    /// Takes the TU's cancellation intent for the INVITE `id`.
    ///
    /// An intent for a transaction that has ended, or whose slot now holds
    /// another INVITE, finds no matching `intent` and is not needed.
    pub(super) fn on_cancel(
        &mut self,
        id: Id,
        intent: &Arc<Intent>,
        done: oneshot::Sender<Result<CancelOutcome, CancelError>>,
    ) {
        let invite =
            self.clients.get_mut(id).and_then(|entry| match &mut entry.tx {
                ClientMachine::Invite(invite)
                    if Arc::ptr_eq(&invite.intent, intent) =>
                {
                    Some(invite)
                }
                _ => None,
            });
        let Some(invite) = invite else {
            let _ = done.send(Ok(CancelOutcome::NotNeeded));
            return;
        };

        match mem::replace(&mut invite.cancel, Cancel::Done) {
            // RFC 3261 section 9.1. No CANCEL before a provisional response.
            Cancel::Reserved(reserved) if invite.tx.is_calling() => {
                invite.cancel = Cancel::Waiting(reserved, done);
            }
            Cancel::Reserved(reserved) if invite.tx.is_proceeding() => {
                self.send_cancel(id, reserved, done);
            }
            // A final response came first, or the INVITE has ended.
            _ => {
                let _ = done.send(Ok(CancelOutcome::NotNeeded));
            }
        }
    }

    /// Sends the CANCEL an intent waited for, after the first provisional.
    pub(super) fn send_waiting_cancel(&mut self, id: Id) {
        let entry = self.clients.get_mut(id).expect("a live client entry");
        let ClientMachine::Invite(invite) = &mut entry.tx else {
            unreachable!("an INVITE entry")
        };
        if let Cancel::Waiting(reserved, done) =
            mem::replace(&mut invite.cancel, Cancel::Done)
        {
            self.send_cancel(id, reserved, done);
        }
    }

    /// Builds the CANCEL of the INVITE `id`, in Proceeding, and sends it to
    /// the INVITE's next hop.
    fn send_cancel(
        &mut self,
        id: Id,
        reserved: Reserved,
        done: oneshot::Sender<Result<CancelOutcome, CancelError>>,
    ) {
        let entry = self.clients.get(id).expect("a live client entry");
        let ClientMachine::Invite(invite) = &entry.tx else {
            unreachable!("an INVITE entry")
        };
        let start = CancelStart {
            request: invite.tx.cancel_request().expect("Proceeding"),
            invite: id,
            intent: invite.intent.clone(),
            reserved,
            done: Some(done),
        };
        let link = entry.link.clone();

        // A closed connection is replaced by a new one to the same next hop,
        // as for the non-2xx ACK. The CANCEL keeps the INVITE's Via.
        match &link.writer {
            Some(writer) if writer.is_closed() => {
                self.send_over_tcp(link.flow.remote, Pending::Cancel(start));
            }
            _ => self.start_cancel(start, link),
        }
    }

    /// Starts the CANCEL's own non-INVITE client transaction on `link`, and
    /// starts the INVITE's cancellation deadline.
    ///
    /// The intent is committed, so a write that fails at once is the CANCEL
    /// transaction's failure, reported through its responses. The TU still
    /// gets the transaction.
    pub(super) fn start_cancel(&mut self, start: CancelStart, link: Link) {
        let CancelStart { request, invite, intent, reserved, done } = start;
        let via = request
            .headers()
            .get(VIA)
            .expect("a CANCEL has the INVITE's Via")
            .clone();
        let key = ClientKey::from_request(&request)
            .expect("the INVITE's Via has a branch");
        let bytes = request.to_bytes();
        drop(request);

        // The reservation covers the table entry. The receipt list is bounded
        // as for retransmissions, and the write may use the headroom that new
        // requests leave for transaction output.
        let sent = if self.client_writes.len()
            < self.config.max_client_transactions
        {
            send_client(self.udp.as_mut(), &link, &bytes, false)
        } else {
            send_on(self.udp.as_mut(), &link, &bytes, false).map(|()| None)
        };
        let now = now();
        let timers = self.config.timers;
        let reliable = link.flow.transport.is_reliable();
        let tx = ClientTransaction::new(bytes, reliable, &timers, now);
        let Reserved { permit, observation } = reserved;
        let delivery = observation.delivery();
        let observed = delivery.observation();
        let flow = link.flow;
        if let Some(writer) = &link.writer {
            *self
                .client_connections
                .entry(writer.connection_id())
                .or_default() += 1;
        }
        let entry = ClientEntry {
            tx: ClientMachine::NonInvite(tx),
            link,
            respond: Some(delivery),
            permit,
        };
        let deadline = entry.deadline();
        debug_assert!(self.clients.find(&key).is_none(), "one CANCEL");
        let id = self.clients.insert(key, entry);
        if let Some(at) = deadline {
            self.timers.push(at, Key::Client(id));
        }
        self.unanswered += 1;

        match sent {
            Ok(Some(receipt)) => {
                self.client_writes.push((receipt, id, observed))
            }
            Ok(None) => {}
            Err(error) => {
                let entry = self.clients.get_mut(id).expect("just inserted");
                entry.tx.end_on_transport_error();
                let completion = entry.answer(Err(
                    if error.kind() == io::ErrorKind::WouldBlock {
                        Error::busy()
                    } else {
                        Error::transport(error)
                    },
                ));
                self.unanswered -= 1;
                self.settle_client(id, None);
                if let Some((delivery, result)) = completion {
                    delivery.send(result);
                }
            }
        }

        // RFC 3261 section 9.1. The INVITE stops waiting 64 T1 from now.
        self.start_cancel_deadline(invite, &intent, now);

        let transaction = observation.finish(via, flow, None);
        if let Some(done) = done {
            let _ = done.send(Ok(CancelOutcome::Sent(transaction)));
        }
    }

    fn start_cancel_deadline(
        &mut self,
        id: Id,
        intent: &Arc<Intent>,
        now: Instant,
    ) {
        let Some(entry) = self.clients.get_mut(id) else { return };
        let before = entry.deadline();
        let ClientMachine::Invite(invite) = &mut entry.tx else { return };
        if !Arc::ptr_eq(&invite.intent, intent) || !invite.tx.is_proceeding() {
            return;
        }
        invite.cancel_deadline = Some(now + self.config.timers.t1() * 64);
        self.settle_client(id, before);
    }

    /// Finds the transaction a new CANCEL targets, after running its due
    /// timer as [`Driver::find_server`] does.
    pub(super) fn find_cancel_target(
        &mut self,
        cancel: &ServerKey,
        now: Instant,
    ) -> Option<Id> {
        let (id, entry) = self
            .servers
            .find_by(cancel, |key| key.is_cancel_target(cancel))?;
        if entry.tx.deadline().is_some_and(|at| at <= now) {
            self.on_timer(Key::Server(id));
        }
        self.servers.get(id).map(|_| id)
    }

    /// Delivers a CANCEL that matched `target`, with a transaction of its own.
    ///
    /// It uses the control capacity, so ordinary requests that hold every
    /// pending slot cannot stop it. Its table entry is the one its INVITE
    /// reserved. A CANCEL of a non-INVITE request, or a second CANCEL after
    /// the first one's transaction ended, needs an ordinary entry. Shutdown
    /// does not refuse it, since it concerns admitted work.
    pub(super) fn on_matched_cancel(
        &mut self,
        request: Request<Bytes>,
        key: ServerKey,
        target: Id,
        flow: Flow,
        link: Link,
    ) {
        let entry = self.servers.get(target).expect("a live target");
        let (target_id, reserved) = (entry.id, entry.tx.cancel_reserved());

        let admitted =
            !self.incoming.is_closed() && (reserved || self.server_room(1));
        let permits = admitted.then(|| {
            let bytes = request_bytes(&request)?;
            Some((
                self.control_events.acquire(bytes)?,
                self.control_work.acquire(bytes)?,
                self.control_routes.acquire(identity_bytes(&request)?)?,
            ))
        });
        let Some(Some((event, work, route))) = permits else {
            self.stateless(&request, &link, SERVICE_UNAVAILABLE);
            return;
        };
        let Some(commands) = self.command_sender.upgrade() else { return };

        if reserved {
            let entry = self.servers.get_mut(target).expect("found above");
            if let ServerMachine::Invite(invite) = &mut entry.tx {
                invite.cancel_reserved = false;
            }
            self.reserved_cancels -= 1;
        }
        let reliable = link.flow.transport.is_reliable();
        let tx = ServerTransaction::new(
            &request,
            reliable,
            &self.config.timers,
            now(),
        );
        let (_, transaction) = self.install_server(
            key,
            ServerMachine::NonInvite(tx),
            link,
            &request,
            work,
            route,
            commands,
        );
        let _ = self.incoming.send(server::Queued {
            event: IncomingEvent::Cancel(IncomingCancel {
                request,
                flow,
                transaction,
                target: target_id,
            }),
            _permit: event,
        });
    }
}
