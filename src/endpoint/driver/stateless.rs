/*!
Stateless reception in the driver.

A [`Reception::Stateless`] endpoint hands every request and response it reads
to the TU, as a stateless proxy needs ([RFC 3261 section 16.11]). Nothing here
looks up or creates a transaction, so a retransmission arrives again, a CANCEL
or ACK is just another request, and a response needs no client transaction.
The driver sends nothing on its own: no 100, no 500, and no 503 when a queue
is full.

What it still does is the transport's part of receiving a request
([RFC 3261 section 18.2.1], [RFC 3581 section 4]). The top Via gets `received`
and `rport`, and the reply route remembers where a response to the request
goes. Proxy request validation ([RFC 3261 section 16.3]) is the TU's.

Each event holds a place in a bounded queue until `recv` returns it. Requests
other than ACK and CANCEL use the ordinary request limits, ACK and CANCEL the
control limits, so a flood of new requests cannot shut them out, and responses
the client response budget. A message beyond its limit is discarded and
counted, and the sender's retransmission tries again.

[`Reception::Stateless`]: crate::endpoint::Reception::Stateless
[RFC 3261 section 16.11]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.11
[RFC 3261 section 18.2.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.1
[RFC 3581 section 4]: https://www.rfc-editor.org/rfc/rfc3581.html#section-4
[RFC 3261 section 16.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.3
*/

use bytes::Bytes;

use super::{Driver, Link, identity_bytes, increment};
use crate::{
    endpoint::{
        admission::request_bytes,
        reply::ReplyRoute,
        routing::{mark_via, reply_flow},
        server::{self, IncomingEvent, ReceivedRequest, ReceivedResponse},
    },
    message::{
        Method,
        header::{VIA, via::Via},
        request::Request,
        response::Response,
    },
    transport::Flow,
};

impl Driver {
    /// Hands a received request to the TU without a transaction.
    pub(super) fn on_stateless_request(
        &mut self,
        mut request: Request<Bytes>,
        link: Link,
    ) {
        // A request without a readable top Via has no reply path, and one with
        // `maddr` would be answered to a multicast group, which signa does not
        // support. Neither could be answered or forwarded back, so neither
        // reaches the TU. They are malformed or out of scope, not overload,
        // and are not counted.
        let Some(value) = request.headers().get(VIA) else { return };
        let Some(via) = Via::top(value) else { return };
        if via.maddr.is_some() {
            return;
        }
        let reply = reply_flow(&via, &link.flow);
        if let Some(marked) = mark_via(value, &via, &link.flow) {
            *request.headers_mut().get_mut(VIA).expect("found above") = marked;
        }
        let source = link.flow;
        let link = Link { flow: reply, writer: link.writer };

        if self.incoming.is_closed() {
            return;
        }
        let ack = request.method() == Method::ACK;
        let control = ack || request.method() == Method::CANCEL;
        let dropped = if ack {
            &self.reception_counters.acks
        } else {
            &self.reception_counters.stateless_requests
        };

        // The queue place lasts until `recv`, the route's until its last clone
        // drops. An ACK route refuses every response, so it copies nothing
        // from the request and takes a place without bytes.
        let Some(bytes) = request_bytes(&request) else { return };
        let queue =
            if control { &self.control_events } else { &self.event_admission };
        let Some(event_permit) = queue.acquire(bytes) else {
            increment(dropped);
            return;
        };
        let identity = if ack { Some(0) } else { identity_bytes(&request) };
        let Some(route_permit) =
            identity.and_then(|bytes| self.routes_admission.acquire(bytes))
        else {
            increment(dropped);
            return;
        };

        let Some(commands) = self.command_sender.upgrade() else { return };
        let route = if ack {
            ReplyRoute::refusing(
                link,
                commands,
                self.reply_admission.0.clone(),
                self.reply_bytes.clone(),
            )
        } else {
            ReplyRoute::new(
                &request,
                link,
                commands,
                self.reply_admission.0.clone(),
                self.reply_bytes.clone(),
            )
        }
        .with_reservations(route_permit, None);

        let event = IncomingEvent::StatelessRequest(ReceivedRequest {
            request,
            flow: source,
            reply: route,
        });
        let _ = self
            .incoming
            .send(server::Queued { event, _permit: event_permit });
    }

    /// Hands a received response to the TU, whether or not this endpoint
    /// sent the request it answers.
    pub(super) fn on_stateless_response(
        &mut self,
        response: Response<Bytes>,
        flow: Flow,
    ) {
        if self.incoming.is_closed() {
            return;
        }
        let bytes = response.encoded_len().unwrap_or(usize::MAX);
        let Some(permit) = self.stateless_responses.acquire(bytes) else {
            increment(&self.reception_counters.stateless_responses);
            return;
        };

        let event = IncomingEvent::StatelessResponse(ReceivedResponse {
            response,
            flow,
        });
        let _ = self.incoming.send(server::Queued { event, _permit: permit });
    }
}
