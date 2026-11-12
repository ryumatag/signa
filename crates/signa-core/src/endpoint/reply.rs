/*!
One-shot responses on an endpoint-issued reply capability.
*/

use std::{error, fmt, io, sync::Arc};

use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

use super::{
    Error, driver::Command, routing::Link, send::SentRequest, server,
};
use crate::{
    message::{
        Method,
        header::{
            CALL_ID, CSEQ, FROM, HeaderMap, HeaderValue, TO, VIA,
            address::has_tag,
        },
        request::Request,
        response::Response,
    },
    transport::{
        Flow,
        budget::{Budget, Permit},
    },
};

/// An opaque capability for sending responses to one received request.
///
/// A route preserves the received UDP local destination or the original TCP
/// writer and its fallback target ([RFC 3261 section 18.2.2]). Clones share
/// the same capability. They cannot substitute a socket or destination.
///
/// [`ReceivedRequest`](super::ReceivedRequest) carries a route, and
/// [`Responder::reply_route`](super::Responder::reply_route) clones one. A
/// route counts against [`Builder::max_responder_handles`] and
/// [`Builder::max_responder_bytes`] until its last clone drops.
///
/// Sending through a route does not advance a server transaction. A stateful
/// proxy must use its live server responder. The TU can use the route for
/// its own UAS 2xx retransmissions.
///
/// [`Builder::max_responder_handles`]: super::Builder::max_responder_handles
/// [`Builder::max_responder_bytes`]: super::Builder::max_responder_bytes
///
/// [RFC 3261 section 18.2.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2
#[derive(Clone)]
pub struct ReplyRoute(Arc<Route>);

struct Route {
    link: Link,
    headers: HeaderMap,
    ack: bool,
    commands: mpsc::UnboundedSender<Command>,
    capacity: Arc<Semaphore>,
    bytes: Budget,
    // The copied identity values above, held for the route's lifetime.
    _identity: Option<Permit>,
    // Untracked application work, which ends at the first accepted final
    // rather than with the last clone. A route kept for logging or later
    // sends must not hold `max_pending_requests` or graceful shutdown.
    work: Option<server::Work>,
}

impl ReplyRoute {
    pub(super) fn new(
        request: &Request<Bytes>,
        link: Link,
        commands: mpsc::UnboundedSender<Command>,
        capacity: Arc<Semaphore>,
        bytes: Budget,
    ) -> ReplyRoute {
        // Selected fields must not pin the received body or TCP read chunk.
        let mut headers = HeaderMap::new();

        for name in [VIA, FROM, TO, CALL_ID, CSEQ] {
            for value in request.headers().get_all(&name) {
                headers.append(
                    name.clone(),
                    HeaderValue::from_built(value.as_str().to_owned()),
                );
            }
        }

        ReplyRoute(Arc::new(Route {
            link,
            headers,
            ack: request.method() == Method::ACK,
            commands,
            capacity,
            bytes,
            _identity: None,
            work: None,
        }))
    }

    /// A route for an ACK, which refuses every response. It copies nothing
    /// from the request, since nothing is ever checked against it.
    pub(super) fn refusing(
        link: Link,
        commands: mpsc::UnboundedSender<Command>,
        capacity: Arc<Semaphore>,
        bytes: Budget,
    ) -> ReplyRoute {
        ReplyRoute(Arc::new(Route {
            link,
            headers: HeaderMap::new(),
            ack: true,
            commands,
            capacity,
            bytes,
            _identity: None,
            work: None,
        }))
    }

    pub(super) fn with_reservations(
        mut self,
        identity: Permit,
        work: Option<super::server::Work>,
    ) -> ReplyRoute {
        let route =
            Arc::get_mut(&mut self.0).expect("new route is not shared");
        route._identity = Some(identity);
        route.work = work;
        self
    }

    /// Sends a response once and waits for its local write result.
    ///
    /// Via, From, Call-ID and CSeq must preserve the route's received values
    /// and row ordering. To must be copied, optionally followed by a `tag`
    /// parameter. Other UA-core response semantics remain the TU's concern.
    /// ACK routes reject responses. Non-100 responses require a To tag.
    /// Routing and identity values are compared byte for byte. Reformatting
    /// equivalent fields is deliberately rejected. At most 64 one-shot replies
    /// are in flight at once, and a further send waits for one to finish.
    /// [`Builder::max_reply_bytes`] bounds their encoded bytes, including
    /// replies waiting for a connection.
    ///
    /// An unpolled future has no effect. Waiting for capacity is cancellation
    /// safe. Enqueue commits the operation. Dropping the future after enqueue
    /// does not undo it, so the caller must not blindly retry. Enqueueing a
    /// final response for an untracked request also ends its place in
    /// [`Builder::max_pending_requests`]. A TCP error may follow a partial
    /// write. Success does not promise delivery to the peer.
    ///
    /// # Errors
    ///
    /// * [`ReplyError::InvalidResponse`] before enqueue, for changed identity
    ///   fields or an encoded length that overflows.
    /// * [`ReplyError::Unsupported`] for a route of an ACK.
    /// * [`ReplyError::Busy`] when [`Builder::max_reply_bytes`] or the
    ///   transport queue is full.
    /// * [`ReplyError::Closed`] once the endpoint has stopped. Existing routes
    ///   remain usable while admitted work drains.
    /// * [`ReplyError::Transport`] for a local I/O error, with its source.
    ///
    /// # Example
    ///
    /// ```
    /// use bytes::Bytes;
    /// use signa_core::{endpoint::{ReplyError, ReplyRoute}, Response};
    ///
    /// async fn send_stateless_reply(
    ///     route: &ReplyRoute,
    ///     response: Response<Bytes>,
    /// ) -> Result<(), ReplyError> {
    ///     route.send(response).await
    /// }
    /// ```
    ///
    /// [`Builder::max_reply_bytes`]: super::Builder::max_reply_bytes
    /// [`Builder::max_pending_requests`]: super::Builder::max_pending_requests
    pub async fn send(
        &self,
        response: Response<Bytes>,
    ) -> Result<(), ReplyError> {
        self.validate(&response)?;
        let len = response.encoded_len().ok_or(ReplyError::InvalidResponse)?;

        let permit = self
            .0
            .capacity
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ReplyError::Closed)?;
        let reservation = self.0.bytes.acquire(len).ok_or(ReplyError::Busy)?;

        let final_response = response.status().is_final();
        let bytes = response.to_bytes_reserved(len);
        // The command owns its encoded bytes. Do not keep the original body
        // and application Extensions alive while waiting for the socket.
        drop(response);
        let (done, result) = oneshot::channel();

        self.0
            .commands
            .send(Command::Reply {
                link: self.0.link.clone(),
                bytes,
                completion: Completion {
                    done: Done::Reply(done),
                    _permit: permit,
                    _endpoint: self.0.commands.clone(),
                    reservation,
                },
            })
            .map_err(|_| ReplyError::Closed)?;
        // Enqueue commits the final, so the untracked request is answered
        // even if this future is dropped now.
        if final_response {
            if let Some(work) = &self.0.work {
                work.finish();
            }
        }

        result.await.map_err(|_| ReplyError::Closed)?
    }

    pub(super) fn validate(
        &self,
        response: &Response<Bytes>,
    ) -> Result<(), ReplyError> {
        if self.0.ack {
            return Err(ReplyError::Unsupported);
        }

        for name in [VIA, FROM, CALL_ID, CSEQ] {
            if self.0.headers.get(&name).is_none()
                || !self
                    .0
                    .headers
                    .get_all(&name)
                    .eq(response.headers().get_all(&name))
            {
                return Err(ReplyError::InvalidResponse);
            }
        }

        let mut original = self.0.headers.get_all(TO);
        let mut supplied = response.headers().get_all(TO);
        let (Some(original), Some(supplied), None, None) = (
            original.next(),
            supplied.next(),
            original.next(),
            supplied.next(),
        ) else {
            return Err(ReplyError::InvalidResponse);
        };

        if original == supplied {
            return if response.status().as_u16() == 100
                || has_tag(original.as_str())
            {
                Ok(())
            } else {
                Err(ReplyError::InvalidResponse)
            };
        }

        if has_tag(original.as_str()) {
            return Err(ReplyError::InvalidResponse);
        }

        let tag = supplied
            .as_str()
            .strip_prefix(original.as_str())
            .and_then(|rest| rest.strip_prefix(";tag="))
            .and_then(siparse::scan::token);

        if !matches!(tag, Some((_, ""))) {
            return Err(ReplyError::InvalidResponse);
        }

        Ok(())
    }
}

impl fmt::Debug for ReplyRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplyRoute").finish_non_exhaustive()
    }
}

/// Why a one-shot response could not be sent.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReplyError {
    /// A required routing or request-identity field was changed or missing.
    InvalidResponse,
    /// This request or routing mode does not support a response.
    Unsupported,
    /// A transport or one-shot reply write budget is exhausted.
    Busy,
    /// The endpoint has ended or is shutting down.
    Closed,
    /// A local transport operation failed, possibly after a partial write.
    Transport(io::Error),
}

impl fmt::Display for ReplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplyError::InvalidResponse => {
                f.write_str("response does not preserve reply-route identity")
            }
            ReplyError::Unsupported => f.write_str("cannot respond to ACK"),
            ReplyError::Busy => f.write_str("write capacity is exhausted"),
            ReplyError::Closed => f.write_str("endpoint is closed"),
            ReplyError::Transport(error) => {
                write!(f, "response transport failed: {error}")
            }
        }
    }
}

impl error::Error for ReplyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ReplyError::Transport(error) => Some(error),
            _ => None,
        }
    }
}

/// A one-shot write in flight, with its reservations, until its local write
/// result reaches the waiting future.
pub(super) struct Completion {
    done: Done,
    _permit: OwnedSemaphorePermit,
    _endpoint: mpsc::UnboundedSender<Command>,
    reservation: Permit,
}

impl Completion {
    pub(super) fn request(
        done: oneshot::Sender<Result<SentRequest, Error>>,
        permit: OwnedSemaphorePermit,
        endpoint: mpsc::UnboundedSender<Command>,
        reservation: Permit,
    ) -> Completion {
        Completion {
            done: Done::Request { done, sent: None },
            _permit: permit,
            _endpoint: endpoint,
            reservation,
        }
    }

    pub(super) fn forward(
        done: oneshot::Sender<Result<(), Error>>,
        permit: OwnedSemaphorePermit,
        endpoint: mpsc::UnboundedSender<Command>,
        reservation: Permit,
    ) -> Completion {
        Completion {
            done: Done::Forward(done),
            _permit: permit,
            _endpoint: endpoint,
            reservation,
        }
    }

    /// Records what a request goes out with, before its write is queued.
    pub(super) fn sent(&mut self, via: HeaderValue, flow: Flow) {
        if let Done::Request { sent, .. } = &mut self.done {
            *sent = Some(SentRequest { via, flow });
        }
    }

    /// Ends a request the driver refused before writing anything.
    pub(super) fn fail(self, error: Error) {
        let Completion { done, _permit, _endpoint, reservation } = self;
        drop(reservation);
        drop(_permit);
        drop(_endpoint);
        match done {
            Done::Request { done, .. } => {
                let _ = done.send(Err(error));
            }
            Done::Forward(done) => {
                let _ = done.send(Err(error));
            }
            Done::Reply(done) => {
                let _ = done.send(Err(ReplyError::Closed));
            }
        }
    }

    pub(super) fn finish(self, result: Result<(), ReplyError>) {
        let Completion { done, _permit, _endpoint, reservation } = self;
        drop(reservation);
        drop(_permit);
        drop(_endpoint);
        match done {
            Done::Reply(done) => {
                let _ = done.send(result);
            }
            Done::Request { done, sent } => {
                let _ = done.send(
                    result
                        .map_err(request_error)
                        .and_then(|()| sent.ok_or_else(Error::closed)),
                );
            }
            Done::Forward(done) => {
                let _ = done.send(result.map_err(request_error));
            }
        }
    }
}

/// The error a one-shot request or forwarded response reports for a write
/// result. Only `Busy` and `Transport` come from a write.
fn request_error(error: ReplyError) -> Error {
    match error {
        ReplyError::Busy => Error::busy(),
        ReplyError::Transport(error) => Error::transport(error),
        ReplyError::Closed
        | ReplyError::InvalidResponse
        | ReplyError::Unsupported => Error::closed(),
    }
}

/// Who waits for a one-shot write: a reply route,
/// [`Endpoint::send_request`](super::Endpoint::send_request), which also
/// learns the Via and flow the driver chose, or
/// [`Endpoint::forward_response`](super::Endpoint::forward_response).
enum Done {
    Reply(oneshot::Sender<Result<(), ReplyError>>),
    Request {
        done: oneshot::Sender<Result<SentRequest, Error>>,
        sent: Option<SentRequest>,
    },
    Forward(oneshot::Sender<Result<(), Error>>),
}

pub(super) struct Admission(pub(super) Arc<Semaphore>);

impl Drop for Admission {
    fn drop(&mut self) {
        self.0.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request<Bytes> {
        Request::builder()
            .method("OPTIONS")
            .uri("sip:bob@example.com")
            .header(
                "Via",
                "SIP/2.0/UDP example.com:9;branch=z9hG4bKroute;rport",
            )
            .header("From", "<sip:alice@example.com>;tag=alice")
            .header("To", "<sip:bob@example.com>")
            .header("Call-ID", "route-test")
            .header("CSeq", "1 OPTIONS")
            .body(Bytes::new())
            .unwrap()
    }

    fn response(request: &Request<Bytes>) -> Response<Bytes> {
        let mut response = Response::reply_to(request)
            .status(200)
            .body(Bytes::new())
            .unwrap();
        let to = response.headers().get(TO).unwrap().as_str().to_owned()
            + ";tag=bob";
        response
            .headers_mut()
            .insert(TO, HeaderValue::from_bytes(to.as_bytes()).unwrap());

        response
    }

    fn route(
        request: &Request<Bytes>,
    ) -> (ReplyRoute, mpsc::UnboundedReceiver<Command>) {
        route_with_budget(
            request,
            Budget::new(crate::transport::WriteLimits::default()),
        )
    }

    fn route_with_budget(
        request: &Request<Bytes>,
        budget: Budget,
    ) -> (ReplyRoute, mpsc::UnboundedReceiver<Command>) {
        let (commands, received) = mpsc::unbounded_channel();
        let link = Link {
            flow: crate::transport::Flow {
                transport: crate::transport::Transport::Udp,
                local: "127.0.0.1:5060".parse().unwrap(),
                remote: "127.0.0.1:9".parse().unwrap(),
            },
            writer: None,
        };

        (
            ReplyRoute::new(
                request,
                link,
                commands,
                Arc::new(Semaphore::new(1)),
                budget,
            ),
            received,
        )
    }

    // No I/O driver is needed.
    #[test]
    fn enqueue_drops_the_original_response_before_waiting_for_io() {
        use std::{
            future::{Future, poll_fn},
            sync::atomic::{AtomicBool, Ordering},
            task::Poll,
        };

        #[derive(Clone)]
        struct Dropped(Arc<AtomicBool>);

        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let request = request();
                let (route, mut commands) = route(&request);
                let dropped = Arc::new(AtomicBool::new(false));
                let mut response = response(&request);
                response.extensions_mut().insert(Dropped(dropped.clone()));
                *response.body_mut() = Bytes::from_static(b"reply body");
                let expected = response.to_bytes();
                let mut send = std::pin::pin!(route.send(response));

                poll_fn(|cx| {
                    assert!(send.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;

                assert!(dropped.load(Ordering::Relaxed));
                let Command::Reply { bytes, completion, .. } =
                    commands.try_recv().unwrap()
                else {
                    panic!("reply command")
                };
                assert_eq!(bytes, expected);
                completion.finish(Ok(()));
                send.await.unwrap();
            });
    }

    #[test]
    fn shared_reply_bytes_remain_charged_after_the_future_is_dropped() {
        use crate::transport::WriteLimits;
        use std::{
            future::{Future, poll_fn},
            task::Poll,
        };

        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let request = request();
                let response = response(&request);
                let len = response.encoded_len().unwrap();
                let budget =
                    Budget::new(WriteLimits { messages: 64, bytes: len });
                let (first, mut commands) =
                    route_with_budget(&request, budget.clone());
                let (second, mut more_commands) =
                    route_with_budget(&request, budget.clone());

                {
                    let mut send =
                        std::pin::pin!(first.send(response.clone()));
                    poll_fn(|cx| {
                        assert!(send.as_mut().poll(cx).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                }
                let mut rejected =
                    std::pin::pin!(second.send(response.clone()));
                poll_fn(|cx| {
                    assert!(matches!(
                        rejected.as_mut().poll(cx),
                        Poll::Ready(Err(ReplyError::Busy))
                    ));
                    Poll::Ready(())
                })
                .await;
                assert!(more_commands.is_empty());
                let Command::Reply { completion, .. } =
                    commands.try_recv().unwrap()
                else {
                    panic!("reply command")
                };
                completion.finish(Ok(()));

                let mut send = std::pin::pin!(second.send(response));
                poll_fn(|cx| {
                    assert!(send.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                let Command::Reply { completion, .. } =
                    more_commands.try_recv().unwrap()
                else {
                    panic!("reply command")
                };
                completion.finish(Ok(()));

                send.await.unwrap();
                assert!(budget.acquire(len).is_some());
            });
    }

    #[test]
    fn oversized_reply_returns_busy_without_consuming_the_operation_slot() {
        use crate::transport::WriteLimits;
        use std::{
            future::{Future, poll_fn},
            task::Poll,
        };

        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let request = request();
                let response = response(&request);
                let len = response.encoded_len().unwrap();
                let budget =
                    Budget::new(WriteLimits { messages: 64, bytes: len });
                let (route, mut commands) =
                    route_with_budget(&request, budget);
                let mut large = response.clone();
                *large.body_mut() = Bytes::from(vec![0; len]);

                let mut rejected = std::pin::pin!(route.send(large));
                poll_fn(|cx| {
                    assert!(matches!(
                        rejected.as_mut().poll(cx),
                        Poll::Ready(Err(ReplyError::Busy))
                    ));
                    Poll::Ready(())
                })
                .await;
                assert!(commands.is_empty());
                assert_eq!(route.0.capacity.available_permits(), 1);

                let mut send = std::pin::pin!(route.send(response));
                poll_fn(|cx| {
                    assert!(send.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                let Command::Reply { completion, .. } =
                    commands.try_recv().unwrap()
                else {
                    panic!("reply command")
                };
                completion.finish(Ok(()));

                send.await.unwrap();
                assert_eq!(route.0.capacity.available_permits(), 1);
            });
    }

    #[test]
    fn invalid_identity_and_ack_are_rejected_before_enqueue() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let request = request();
                let (reply, received) = route(&request);

                for name in [VIA, FROM, CALL_ID, CSEQ, TO] {
                    let mut changed = response(&request);
                    changed
                        .headers_mut()
                        .insert(name, HeaderValue::from_static("different"));
                    assert!(matches!(
                        reply.send(changed).await,
                        Err(ReplyError::InvalidResponse)
                    ));
                }
                assert!(received.is_empty());

                let mut ack = request;
                *ack.method_mut() = Method::ACK;
                let (reply, received) = route(&ack);
                assert!(matches!(
                    reply.send(response(&ack)).await,
                    Err(ReplyError::Unsupported)
                ));
                assert!(received.is_empty());
            });
    }

    #[test]
    fn to_tags_cannot_be_changed_or_duplicated_and_non_100_needs_a_tag() {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let request = request();
                let (reply, received) = route(&request);
                let tagless = Response::reply_to(&request)
                    .status(200)
                    .body(Bytes::new())
                    .unwrap();

                assert!(matches!(
                    reply.send(tagless).await,
                    Err(ReplyError::InvalidResponse)
                ));
                assert!(received.is_empty());

                let mut tagged = request;
                tagged.headers_mut().insert(
                    TO,
                    HeaderValue::from_static(
                        "<sip:bob@example.com>;tag=existing",
                    ),
                );
                let (reply, received) = route(&tagged);
                let duplicate = response(&tagged);

                assert!(matches!(
                    reply.send(duplicate).await,
                    Err(ReplyError::InvalidResponse)
                ));
                assert!(received.is_empty());
            });
    }
}
