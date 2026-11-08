/*!
INVITE transactions in the driver, and the ACKs that go with them.

The machines in [`crate::transaction::invite`] decide the protocol. This module
carries out what they return: responses to the TU, the non-2xx ACK on the
INVITE's next hop, timers, and ACKs received for the TU. The CANCEL of an
INVITE lives in the sibling `cancels` module.

[RFC 3261 section 17.1.1] as amended by [RFC 6026 section 8.4] covers the
client, and [section 17.2.1] with [RFC 6026 sections 8.5 and 8.7] the server.

[RFC 3261 section 17.1.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1
[RFC 6026 section 8.4]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.4
[section 17.2.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.1
[RFC 6026 sections 8.5 and 8.7]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.7
*/

use std::{io, time::Instant};

use bytes::Bytes;

use super::{
    has_identity, send_on, Cancel, ClientEntry, ClientMachine, Driver, Link,
    Pending, ServerMachine,
};
use crate::{
    endpoint::{
        admission::request_bytes,
        error::Error,
        server::{self, IncomingEvent, ReceivedAck},
        table::Id,
    },
    message::{request::Request, response::Response},
    transaction::{invite, key::ServerKey},
    transport::{tcp, Flow},
};

impl Driver {
    /// Processes a response matched to an INVITE client transaction.
    ///
    /// Provisional responses and every accepted 2xx go to the TU, which also
    /// gets the first non-2xx final. That ends observation, while the machine
    /// stays for Timer D to acknowledge retransmissions of it. The 2xx keep the
    /// stream open until Timer M. An INVITE observer that overflowed sees
    /// nothing more, but the machine still sends its ACKs.
    pub(super) fn on_invite_response(
        &mut self,
        id: Id,
        response: Response<Bytes>,
        before: Option<Instant>,
        now: Instant,
    ) {
        let timers = self.config.timers;
        let entry = self.clients.get_mut(id).expect("a live client entry");
        let ClientEntry { tx, link, respond, permit } = entry;
        let ClientMachine::Invite(invite) = tx else {
            unreachable!("an INVITE entry")
        };

        let mut completion = None;
        let mut ack = None;
        let mut cancel = false;
        match invite.tx.on_response(response, &timers, now) {
            invite::ClientEvent::Provisional(response) => {
                // The machine stopped retransmitting and dropped the request.
                permit.release_bytes();
                if let Some(delivery) = respond {
                    delivery.response(response);
                }
                cancel = matches!(invite.cancel, Cancel::Waiting(..));
            }
            invite::ClientEvent::Final { response, ack: bytes } => {
                permit.release_bytes();
                invite.cancel_not_needed();
                invite.cancel_deadline = None;
                if invite.mark_answered() {
                    self.unanswered -= 1;
                }
                if response.status().is_success() {
                    if let Some(delivery) = respond {
                        delivery.response(response);
                    }
                } else {
                    completion = respond.take().map(|d| (d, Ok(response)));
                }
                ack = bytes.map(|bytes| (link.clone(), bytes));
            }
            // A retransmitted non-2xx in Completed gets the cached ACK.
            invite::ClientEvent::Send(bytes) => {
                ack = Some((link.clone(), bytes))
            }
            // A non-2xx without To cannot be acknowledged, and the RFC 6026
            // states discard what they do not take.
            invite::ClientEvent::InvalidResponse
            | invite::ClientEvent::None
            | invite::ClientEvent::Timeout
            | invite::ClientEvent::TransportError
            | invite::ClientEvent::Terminated => {}
        }

        if let Some((link, bytes)) = ack {
            self.send_ack(id, &link, bytes);
        }
        if cancel {
            self.send_waiting_cancel(id);
        }
        self.settle_client(id, before);
        if let Some((delivery, result)) = completion {
            delivery.send(result);
        }
    }

    /// Runs an INVITE client's timers: A, B, D, M, and the cancellation
    /// deadline.
    pub(super) fn on_invite_client_timer(
        &mut self,
        id: Id,
        before: Option<Instant>,
        now: Instant,
    ) {
        let timers = self.config.timers;
        let entry = self.clients.get_mut(id).expect("a live client entry");
        let ClientEntry { tx, respond, permit, .. } = entry;
        let ClientMachine::Invite(invite) = tx else {
            unreachable!("an INVITE entry")
        };

        let mut completion = None;
        let mut retransmit = None;
        // RFC 3261 section 9.1. Without a final response 64 T1 after the
        // CANCEL, the INVITE is given up. A final that came first cleared the
        // deadline.
        if invite.cancel_deadline.is_some_and(|at| at <= now) {
            invite.cancel_deadline = None;
            if invite.tx.abandon() {
                if invite.mark_answered() {
                    self.unanswered -= 1;
                }
                permit.release_bytes();
                completion =
                    respond.take().map(|d| (d, Err(Error::cancel_timeout())));
            }
        }
        if !invite.tx.is_terminated() {
            match invite.tx.on_timeout(&timers, now) {
                invite::ClientEvent::Send(request) => {
                    retransmit = Some(request)
                }
                // Timer B, which ends Calling only.
                invite::ClientEvent::Timeout => {
                    invite.cancel_not_needed();
                    if invite.mark_answered() {
                        self.unanswered -= 1;
                    }
                    permit.release_bytes();
                    completion =
                        respond.take().map(|d| (d, Err(Error::timeout())));
                }
                _ => {}
            }
        }

        if let Some(request) = retransmit {
            if let Some(error) = self.retransmit_client(id, &request) {
                let entry =
                    self.clients.get_mut(id).expect("a live client entry");
                let ClientMachine::Invite(invite) = &mut entry.tx else {
                    unreachable!("an INVITE entry")
                };
                invite.tx.on_transport_error();
                invite.cancel_not_needed();
                if invite.mark_answered() {
                    self.unanswered -= 1;
                }
                completion = entry.answer(Err(Error::transport(error)));
            }
        }

        self.settle_client(id, before);
        if let Some((delivery, result)) = completion {
            delivery.send(result);
        }
    }

    /// Sends the transaction ACK for a non-2xx on the INVITE's next hop
    /// ([RFC 3261 section 17.1.1.3]).
    ///
    /// The ACK keeps the INVITE's Via, so a new connection does not change
    /// the transaction. A TCP connection that has closed since, which happens
    /// when the final arrived on a connection the server opened to the
    /// listener ([RFC 3261 section 18.2.2]), is replaced by a new one to the
    /// INVITE's target. The address the final came from is never a target.
    ///
    /// [RFC 3261 section 17.1.1.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.3
    /// [RFC 3261 section 18.2.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2
    fn send_ack(&mut self, id: Id, link: &Link, ack: Bytes) {
        let error = match &link.writer {
            Some(writer) => {
                let reconnect = writer.is_closed()
                    || matches!(
                        writer.send(ack.clone()),
                        Err(tcp::SendError::Closed)
                    );
                if reconnect {
                    // A refused or failed connection loses this ACK as UDP
                    // would. A reliable INVITE has already ended, and the
                    // server's Timer H covers it.
                    self.send_over_tcp(link.flow.remote, Pending::Ack(ack));
                }
                None
            }
            None => match send_on(self.udp.as_mut(), link, &ack, false) {
                Err(error) if error.kind() != io::ErrorKind::WouldBlock => {
                    Some(error)
                }
                _ => None,
            },
        };

        // The final was delivered already. A failed ACK ends Completed early,
        // as RFC 3261 section 17.1.1.2 has a transport error do.
        if error.is_some() {
            if let Some(entry) = self.clients.get_mut(id) {
                if let ClientMachine::Invite(invite) = &mut entry.tx {
                    invite.tx.on_transport_error();
                }
            }
        }
    }

    /// Runs an INVITE server's timers: G, H, I and L.
    pub(super) fn on_invite_server_timer(&mut self, id: Id, now: Instant) {
        let timers = self.config.timers;
        let entry = self.servers.get_mut(id).expect("a live server entry");
        let ServerMachine::Invite(tx) = &mut entry.tx else {
            unreachable!("an INVITE entry")
        };
        let shared =
            entry.shared.clone().expect("an INVITE keeps its TU state");

        match tx.on_timeout(&timers, now) {
            // Timer G retransmits the non-2xx. A refused copy is like a lost
            // datagram, and G or the request's retransmission repeats it.
            invite::ServerEvent::Send(bytes) => {
                let link = entry.link.clone();
                self.send_generated(id, &link, bytes, &shared);
            }
            invite::ServerEvent::Timeout => shared.ack_timeout(),
            _ => {}
        }
    }

    /// Takes an ACK. One for a non-2xx is the INVITE transaction's, which
    /// absorbs it. One that matches an INVITE in Accepted, or no transaction,
    /// goes to the TU ([RFC 3261 section 17.2.3], [RFC 6026 section 8.7]).
    ///
    /// No ACK gets a response on any path. Without control capacity, a TU, or
    /// a usable identity, it is discarded.
    ///
    /// [RFC 3261 section 17.2.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.3
    /// [RFC 6026 section 8.7]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.7
    pub(super) fn on_ack(
        &mut self,
        request: Request<Bytes>,
        key: Option<&ServerKey>,
        flow: Flow,
        now: Instant,
    ) {
        if let Some(id) = key.and_then(|key| self.find_server(key, now)) {
            let timers = self.config.timers;
            let entry = self.servers.get_mut(id).expect("found above");
            let before = entry.tx.deadline();
            // The key names INVITE, so only an INVITE entry can match.
            let ServerMachine::Invite(tx) = &mut entry.tx else { return };
            let event = tx.on_ack(&timers, now);
            self.settle_server(id, before);
            if event != invite::ServerEvent::Ack {
                return;
            }
        }

        if self.incoming.is_closed() || !has_identity(&request) {
            return;
        }
        let Some(bytes) = request_bytes(&request) else { return };
        let Some(permit) = self.control_events.acquire(bytes) else { return };
        let _ = self.incoming.send(server::Queued {
            event: IncomingEvent::Ack(ReceivedAck { request, flow }),
            _permit: permit,
        });
    }
}
