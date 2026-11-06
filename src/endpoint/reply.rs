/*!
One-shot responses on an endpoint-issued reply capability.
*/

use std::{error, fmt, io, sync::Arc};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

use crate::{
    endpoint::driver::{Command, Link},
    message::{
        header::{
            address::has_tag, HeaderMap, HeaderValue, CALL_ID, CSEQ, FROM, TO,
            VIA,
        },
        request::Request,
        response::Response,
        Method,
    },
};

/// An opaque capability for sending responses to one received request.
///
/// A route preserves the received UDP local destination or the original TCP
/// writer and its fallback target ([RFC 3261 section 18.2.2]). Clones share
/// the same capability. They cannot substitute a socket or destination.
///
/// Routes will be issued by the incoming TU envelopes. The current Service
/// interface does not expose them. This primitive precedes that API change.
/// Sending through a route does not advance a server transaction. A stateful
/// proxy must use its live server responder. The TU can use the route for
/// its own UAS 2xx retransmissions.
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
}

impl ReplyRoute {
    pub(super) fn new(
        request: &Request<Bytes>,
        link: Link,
        commands: mpsc::UnboundedSender<Command>,
        capacity: Arc<Semaphore>,
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
        }))
    }

    /// Sends a response once and waits for its local write result.
    ///
    /// Via, From, Call-ID and CSeq must preserve the route's received values
    /// and row ordering. To must be copied, optionally followed by a `tag`
    /// parameter. Other UA-core response semantics remain the TU's concern.
    /// ACK routes reject responses. Non-100 responses require a To tag.
    /// Routing and identity values are compared byte for byte. Reformatting
    /// equivalent fields is deliberately rejected. The endpoint currently
    /// admits at most 64 one-shot replies through their local completion.
    ///
    /// An unpolled future has no effect. Waiting for capacity is cancellation
    /// safe. Enqueue commits the operation. Dropping the future after enqueue
    /// does not undo it, so the caller must not blindly retry. A TCP error may
    /// follow a partial write. Success does not promise delivery to the peer.
    ///
    /// # Errors
    ///
    /// Returns an invalid-response error before enqueue for changed identity
    /// fields, busy for a full transport queue, closed when the endpoint ends,
    /// or a transport error retaining the I/O source.
    ///
    /// ```
    /// use bytes::Bytes;
    /// use signa::{endpoint::{ReplyError, ReplyRoute}, Response};
    ///
    /// async fn send_stateless_reply(
    ///     route: &ReplyRoute,
    ///     response: Response<Bytes>,
    /// ) -> Result<(), ReplyError> {
    ///     route.send(response).await
    /// }
    /// ```
    pub async fn send(
        &self,
        response: Response<Bytes>,
    ) -> Result<(), ReplyError> {
        self.validate(&response)?;

        let permit = self
            .0
            .capacity
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ReplyError::Closed)?;

        let (done, result) = oneshot::channel();

        self.0
            .commands
            .send(Command::Reply {
                link: self.0.link.clone(),
                bytes: response.to_bytes(),
                completion: Completion {
                    done,
                    _permit: permit,
                    _endpoint: self.0.commands.clone(),
                },
            })
            .map_err(|_| ReplyError::Closed)?;

        result.await.map_err(|_| ReplyError::Closed)?
    }

    fn validate(&self, response: &Response<Bytes>) -> Result<(), ReplyError> {
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
    /// The transport queue is full.
    Busy,
    /// The endpoint has ended or is shutting down.
    Closed,
    /// A local transport operation failed, possibly after a partial write.
    Transport(io::Error),
}

impl fmt::Display for ReplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidResponse => {
                f.write_str("response does not preserve reply-route identity")
            }
            Self::Unsupported => f.write_str("cannot respond to ACK"),
            Self::Busy => f.write_str("transport queue is full"),
            Self::Closed => f.write_str("endpoint is closed"),
            Self::Transport(error) => {
                write!(f, "response transport failed: {error}")
            }
        }
    }
}

impl error::Error for ReplyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

pub(super) struct Completion {
    done: oneshot::Sender<Result<(), ReplyError>>,
    _permit: OwnedSemaphorePermit,
    _endpoint: mpsc::UnboundedSender<Command>,
}

impl Completion {
    pub(super) fn finish(self, result: Result<(), ReplyError>) {
        let _ = self.done.send(result);
    }
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
            ),
            received,
        )
    }

    // No I/O driver is needed. Keeping it disabled also permits Miri on macOS.
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
