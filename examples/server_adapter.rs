/*!
An application-owned, bounded Tower dispatcher and a responder wrapper.

The service is not Clone. Readiness is polled on the instance that is called.
The associated response future delegates to signa without boxing that operation.
Application handler tasks and their concurrency bound live outside the endpoint.
*/

use std::{
    convert::Infallible,
    future::{poll_fn, Future},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use signa::{
    endpoint::{
        Endpoint, Incoming, IncomingEvent, Responder, ResponseSubmission,
        SubmitError, Target,
    },
    message::header::Tag,
    transport::Transport,
    Request, Response,
};
use tokio::sync::Semaphore;
use tower_service::Service;

trait ResponseSender {
    type Send<'a>: Future<Output = Result<(), SubmitError>> + Send
    where
        Self: 'a;

    fn send(&self, response: Response<Bytes>) -> Self::Send<'_>;
}

struct LoggedResponder(Responder);

impl ResponseSender for LoggedResponder {
    type Send<'a> = ResponseSubmission<'a>;

    fn send(&self, response: Response<Bytes>) -> ResponseSubmission<'_> {
        let submission = self.0.respond(response);
        println!("submitting {:?}", submission.id());
        submission
    }
}

struct Envelope<R> {
    request: Request<Bytes>,
    responder: R,
}

struct Echo {
    ready: bool,
    calls: usize,
}

impl Service<Envelope<LoggedResponder>> for Echo {
    type Response = ();
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<(), Infallible>> + Send>>;

    fn poll_ready(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), Infallible>> {
        self.ready = true;
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, envelope: Envelope<LoggedResponder>) -> Self::Future {
        assert!(
            std::mem::replace(&mut self.ready, false),
            "readiness is checked on this instance"
        );
        self.calls += 1;
        Box::pin(async move {
            let response = Response::reply_to(&envelope.request)
                .status(200)
                .to_tag(Tag::random())
                .body(Bytes::new())
                .expect("an admitted request has one To header");

            if let Err(error) = envelope.responder.send(response).await {
                eprintln!("response rejected: {error}");
            }
            Ok(())
        })
    }
}

async fn dispatch(mut incoming: Incoming, mut service: Echo) {
    let capacity = Arc::new(Semaphore::new(8));
    loop {
        let permit = capacity
            .clone()
            .acquire_owned()
            .await
            .expect("application semaphore stays open");
        let Some(event) = incoming.recv().await else { break };
        let IncomingEvent::Request(envelope) = event else { continue };
        let (responder, _) = envelope.transaction.into_parts();
        poll_fn(|cx| service.poll_ready(cx))
            .await
            .expect("service error is Infallible");
        let future = service.call(Envelope {
            request: envelope.request,
            responder: LoggedResponder(responder),
        });

        tokio::spawn(async move {
            let _permit = permit;
            future.await.expect("service error is Infallible");
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (server, incoming) =
        Endpoint::builder().udp("127.0.0.1:0".parse()?).bind()?;
    let handling =
        tokio::spawn(dispatch(incoming, Echo { ready: false, calls: 0 }));
    let (client, _incoming) =
        Endpoint::builder().udp("127.0.0.1:0".parse()?).bind()?;
    let target =
        Target::new(Transport::Udp, server.udp_addr().expect("UDP bound"));
    let request = Request::builder()
        .method("OPTIONS")
        .uri("sip:bob@example.com")
        .header("From", "<sip:alice@example.com>;tag=alice")
        .header("To", "<sip:bob@example.com>")
        .header("Call-ID", "adapter-example")
        .header("CSeq", "1 OPTIONS")
        .body(Bytes::new())?;

    let (_control, mut responses) =
        client.start(request, target).await?.into_parts();
    let response = responses.next().await.expect("transaction outcome")?;
    assert_eq!(response.status().as_u16(), 200);
    server.shutdown(Duration::from_secs(1)).await;
    handling.await?;

    Ok(())
}
