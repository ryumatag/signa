/*!
The client side of an endpoint.
*/

use std::{
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use tower_service::Service;

use super::{admission::ClientAdmission, driver::Command, Error, Transport};
use crate::message::{header::CSEQ, request::Request, response::Response};

/// Sends requests to one next hop and returns their final responses.
///
/// A client is bound to one next hop, an address and a transport, like
/// hyper's `SendRequest` is bound to one connection. Which next hop a request
/// goes to is for a layer above to decide, with RFC 3263 or a router, and
/// that layer holds one client per hop. [`Endpoint::client`] makes one.
///
/// # What a request becomes
///
/// `Client` implements [`Service`]. It is always ready. [`Service::call`]
/// validates CSeq presence and reserves an endpoint-wide request count and
/// content-byte budget before enqueue. Saturation returns [`Error::is_busy`]
/// without queuing or sending.
///
/// The driver can also return Busy when route or connection admission is full,
/// before sending the request. Successful enqueue commits the operation even
/// when the returned future is never polled. The endpoint adds the topmost
/// `Via` with a new branch, starts a client transaction, and sends the
/// request.
///
/// The future resolves with the final response, or with an [`Error`] when
/// Timer F fires first or the transport fails. Provisional responses are not
/// returned. A non-INVITE request gets at most a 100 that says nothing
/// (RFC 4320), so there is nothing to return before the final response.
///
/// # Dropping the future
///
/// Dropping the future does not end the transaction. The endpoint keeps
/// retransmitting until a final response arrives or Timer F fires, as
/// RFC 3261 section 17.1.2 requires. A timeout or retry layer around a
/// `Client` therefore starts a new transaction each time, with a new branch,
/// while the old one runs on. That is what the RFC asks of a UA that gives up
/// on a non-INVITE request, but it is not free, and a retry layer that does
/// not know SIP should not be put around a client without thought.
///
/// Dropping the future does not release admission. Request bytes stay reserved
/// while waiting for a connect and while the machine retains its request.
/// The count remains reserved through Timer K after a UDP final response.
/// A terminal outcome returns its count before waking the response future.
///
/// # What the request needs
///
/// The request must have a `CSeq`, since responses are matched by its method.
/// RFC 3261 section 8.1.1 requires `To`, `From`, `Call-ID`, and `Max-Forwards`
/// too, but signa does not check them. Nothing in it depends on them.
///
/// [`Endpoint::client`]: super::Endpoint::client
#[derive(Clone, Debug)]
pub struct Client {
    commands: mpsc::UnboundedSender<Command>,
    admission: ClientAdmission,
    transport: Transport,
    next_hop: SocketAddr,
}

impl Client {
    pub(super) fn new(
        commands: mpsc::UnboundedSender<Command>,
        admission: ClientAdmission,
        transport: Transport,
        next_hop: SocketAddr,
    ) -> Client {
        Client { commands, admission, transport, next_hop }
    }

    /// The transport the client sends over.
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// The address the client sends to.
    pub fn next_hop(&self) -> SocketAddr {
        self.next_hop
    }
}

impl Service<Request<Bytes>> for Client {
    type Response = Response<Bytes>;
    type Error = Error;
    type Future = ResponseFuture;

    /// Always ready. `call` reserves count and byte capacity without waiting,
    /// and returns a failed future when admission is full or closed.
    fn poll_ready(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Bytes>) -> ResponseFuture {
        if self.commands.is_closed() {
            return ResponseFuture::failed(Error::closed());
        }
        if !request.headers().contains_key(CSEQ) {
            return ResponseFuture::failed(Error::missing(CSEQ));
        }
        let permit = match self.admission.acquire(&request) {
            Ok(permit) => permit,
            Err(error) => return ResponseFuture::failed(error),
        };

        let (respond, response) = oneshot::channel();
        let command = Command::Send {
            request,
            transport: self.transport,
            next_hop: self.next_hop,
            respond,
            permit,
        };
        let state = match self.commands.send(command) {
            Ok(()) => State::Waiting(response),
            Err(_) => State::Failed(Some(Error::closed())),
        };

        ResponseFuture { state }
    }
}

/// The final response to a request sent through a [`Client`].
///
/// See [`Client`] for what dropping it does, and does not do.
pub struct ResponseFuture {
    state: State,
}

enum State {
    Waiting(oneshot::Receiver<Result<Response<Bytes>, Error>>),
    /// The error to return. Taken when the future is polled.
    Failed(Option<Error>),
}

impl ResponseFuture {
    fn failed(error: Error) -> ResponseFuture {
        ResponseFuture { state: State::Failed(Some(error)) }
    }
}

impl Future for ResponseFuture {
    type Output = Result<Response<Bytes>, Error>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        match &mut self.state {
            State::Waiting(response) => {
                Pin::new(response).poll(cx).map(|received| match received {
                    Ok(result) => result,
                    // The endpoint dropped the transaction without answering,
                    // which only happens when it stops.
                    Err(_) => Err(Error::closed()),
                })
            }
            State::Failed(err) => {
                Poll::Ready(Err(err.take().expect("polled after completion")))
            }
        }
    }
}

impl fmt::Debug for ResponseFuture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.state {
            State::Waiting(_) => "ResponseFuture(waiting)",
            State::Failed(_) => "ResponseFuture(failed)",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(body: &'static [u8]) -> Request<Bytes> {
        Request::builder()
            .method("OPTIONS")
            .uri("sip:example.com")
            .header("CSeq", "1 OPTIONS")
            .body(Bytes::from_static(body))
            .unwrap()
    }

    fn client(
        count: usize,
        bytes: usize,
    ) -> (Client, mpsc::UnboundedReceiver<Command>) {
        let (commands, received) = mpsc::unbounded_channel();
        (
            Client::new(
                commands,
                ClientAdmission::new(count, bytes),
                Transport::Tcp,
                "127.0.0.1:9".parse().unwrap(),
            ),
            received,
        )
    }

    fn failure(future: ResponseFuture) -> Error {
        match future.state {
            State::Failed(Some(error)) => error,
            _ => panic!("expected immediate admission failure"),
        }
    }

    #[test]
    fn a_stalled_driver_cannot_accumulate_more_commands_than_admission() {
        let (mut client, mut received) = client(2, usize::MAX);
        let mut clone = client.clone();
        let first = client.call(request(b""));
        let second = clone.call(request(b""));

        drop(first);
        drop(second);
        for _ in 0..100 {
            assert!(failure(client.call(request(b""))).is_busy());
        }
        assert_eq!(received.len(), 2);

        drop(received.try_recv().unwrap());

        drop(clone.call(request(b"")));
        assert_eq!(received.len(), 2);
    }

    #[test]
    fn a_byte_rejection_rolls_back_count_without_queuing_or_encoding() {
        let (mut client, mut received) = client(2, 50);
        assert!(failure(client.call(request(&[b'x'; 100]))).is_busy());
        assert!(received.is_empty());

        drop(client.call(request(b"")));
        assert!(failure(client.call(request(b""))).is_busy());
        assert_eq!(received.len(), 1);

        drop(received.try_recv().unwrap());

        drop(client.call(request(b"")));
        assert_eq!(received.len(), 1);
    }

    #[test]
    fn invalid_input_and_a_closed_driver_never_reserve_capacity() {
        let (mut client, received) = client(1, usize::MAX);
        let missing = Request::builder()
            .method("OPTIONS")
            .uri("sip:example.com")
            .body(Bytes::new())
            .unwrap();

        assert_eq!(
            failure(client.call(missing)).to_string(),
            "the request has no CSeq"
        );
        assert!(received.is_empty());
        drop(client.call(request(b"")));
        assert_eq!(received.len(), 1);

        drop(received);

        assert!(failure(client.call(request(b""))).is_closed());
    }
}
