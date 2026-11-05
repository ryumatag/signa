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

use super::{driver::Command, Error, Transport};
use crate::{Request, Response};

/// Sends requests to one next hop and returns their final responses.
///
/// A client is bound to one next hop, an address and a transport, like
/// hyper's `SendRequest` is bound to one connection. Which next hop a request
/// goes to is for a layer above to decide, with RFC 3263 or a router, and
/// that layer holds one client per hop. [`Endpoint::client`] makes one.
///
/// # What a request becomes
///
/// `Client` implements [`Service`]. It is always ready, and [`Service::call`]
/// hands the request to the endpoint without waiting. The endpoint adds the
/// topmost `Via` with a new branch, starts a client transaction, and sends the
/// request. The future resolves with the final response, or with an
/// [`Error`] when Timer F fires first or the transport fails. Provisional
/// responses are not returned. A non-INVITE request gets at most a 100 that
/// says nothing (RFC 4320), so there is nothing to return before the final
/// response.
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
    transport: Transport,
    next_hop: SocketAddr,
}

impl Client {
    pub(super) fn new(
        commands: mpsc::UnboundedSender<Command>,
        transport: Transport,
        next_hop: SocketAddr,
    ) -> Client {
        Client { commands, transport, next_hop }
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

    /// Always ready. The endpoint limits the client transactions it holds and
    /// refuses a request beyond the limit with [`Error::is_busy`], so there
    /// is nothing to wait for here.
    fn poll_ready(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Bytes>) -> ResponseFuture {
        let (respond, response) = oneshot::channel();
        let command = Command::Send {
            request,
            transport: self.transport,
            next_hop: self.next_hop,
            respond,
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
