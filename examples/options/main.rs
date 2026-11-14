/*!
The smallest transaction user: a UAS that answers non-INVITE requests.

The server endpoint answers OPTIONS over UDP and TCP, and a client endpoint on
the loopback sends one over each. The server then shuts down gracefully, which
over UDP waits for Timer J to end the transaction it answered.

Pass `--t1-ms 50` for a quicker run. With RFC 3261's 500 ms T1, Timer J is
32 s.

# What signa does and what the TU does

signa's non-INVITE server transaction absorbs retransmitted requests, resends
the final response for them, and on UDP sends the 100 Trying of
[RFC 4320 section 4] if the TU takes too long. It keeps the final response for
Timer J over UDP and ends at once over TCP ([RFC 3261 section 17.2.2]).

The TU:

* Splits each [`ServerTransaction`] into a [`Responder`], to send responses,
  and [`ServerEvents`], to see what happens to them afterwards.
* Answers with exactly one final response, with a To tag of its own since the
  request has none ([RFC 3261 section 8.2.6.2]).
  [`response::Builder::to_tag`] keeps a tag the request already has.
* Learns from `respond` only that the driver accepted the response, not that
  the peer got it. A failed write shows up later in `ServerEvents`, and over
  UDP a lost response is recovered by the client's retransmission.

RFC 4320 also limits what the TU may send. A 100 over UDP before the driver's
own is due is refused with [`SubmitError::TooEarly`], and a provisional
response other than 100 with [`SubmitError::ProhibitedStatus`]. Over TCP an
early 100 is fine.

[RFC 4320 section 4]: https://www.rfc-editor.org/rfc/rfc4320.html#section-4
[RFC 3261 section 17.2.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.2
[RFC 3261 section 8.2.6.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-8.2.6.2
[`ServerTransaction`]: signa::endpoint::ServerTransaction
[`Responder`]: signa::endpoint::Responder
[`ServerEvents`]: signa::endpoint::ServerEvents
[`response::Builder::to_tag`]: signa::message::response::Builder::to_tag
[`SubmitError::TooEarly`]: signa::endpoint::SubmitError::TooEarly
[`SubmitError::ProhibitedStatus`]: signa::endpoint::SubmitError::ProhibitedStatus
*/

use std::{env, error::Error, time::Duration};

use bytes::Bytes;
use signa::{
    Request, Response,
    endpoint::{
        Endpoint, IncomingEvent, ServerEvent, ServerTransaction,
        ShutdownOutcome, SubmitError, Target,
    },
    message::header::Tag,
    transaction::Timers,
    transport::{Flow, Transport},
};

type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let timers = timers_from_args()?;
    let (server, mut incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse()?)
        .tcp("127.0.0.1:0".parse()?)
        .timers(timers)
        .bind()?;

    // The receive loop hands each request to a task of its own, so a slow
    // answer never holds up the next request.
    let serving = tokio::spawn(async move {
        while let Some(event) = incoming.recv().await {
            if let IncomingEvent::Request(envelope) = event {
                tokio::spawn(answer(
                    envelope.request,
                    envelope.received.flow(),
                    envelope.transaction,
                ));
            }
        }
    });

    let (client_end, _client_incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse()?)
        .timers(timers)
        .bind()?;

    for (transport, next_hop) in [
        (Transport::Udp, server.udp_addr().expect("UDP bound")),
        (Transport::Tcp, server.tcp_addr().expect("TCP bound")),
    ] {
        let target = Target::new(transport, next_hop);
        let request = Request::builder()
            .method("OPTIONS")
            .uri(format!("sip:bob@{next_hop}").as_str())
            .header("From", "<sip:alice@127.0.0.1>;tag=alice")
            .header("To", "<sip:bob@127.0.0.1>")
            .header("Call-ID", format!("example-{transport}").as_str())
            .header("CSeq", "1 OPTIONS")
            .body(Bytes::new())?;

        let (_control, mut responses) =
            client_end.start(request, target.clone()).await?.into_parts();
        let mut response =
            responses.next().await.expect("transaction outcome")?;
        while response.status().is_provisional() {
            println!("client: {} over {transport}", response.status());
            response = responses.next().await.expect("final outcome")?;
        }
        println!("client: {} over {transport}", response.status());
        assert_eq!(response.status().as_u16(), 200);
    }

    // The TCP transaction ended with its response. The UDP one keeps its
    // response for Timer J, and the drain waits for it.
    let outcome = server.shutdown(Duration::from_secs(40)).await;
    println!("server: shutdown {outcome:?}");
    assert_eq!(outcome, ShutdownOutcome::Drained);
    serving.await?;
    Ok(())
}

/// Answers one request and reports what happens to its transaction.
async fn answer(
    request: Request<Bytes>,
    flow: Flow,
    transaction: ServerTransaction,
) {
    println!(
        "server: {} from {} over {}",
        request.method(),
        flow.remote,
        flow.transport
    );
    let (responder, mut events) = transaction.into_parts();

    // RFC 4320 section 4 keeps a TU from sending a 100 over UDP before the
    // driver's own would be due.
    let trying = Response::reply_to(&request)
        .status(100)
        .body(Bytes::new())
        .expect("a valid response");
    match responder.respond(trying).await {
        Ok(()) => {
            println!("server: early 100 accepted over {}", flow.transport)
        }
        Err(SubmitError::TooEarly) => {
            println!("server: early 100 refused over {}", flow.transport)
        }
        Err(error) => println!("server: 100 not accepted: {error}"),
    }

    let response = Response::reply_to(&request)
        .status(200)
        .header("Allow", "OPTIONS")
        .to_tag(Tag::random())
        .body(Bytes::new())
        .expect("a valid response");
    // Accepted by the driver. Whether the client gets it is another matter.
    if let Err(error) = responder.respond(response).await {
        println!("server: 200 not accepted: {error}");
        return;
    }

    while let Some(event) = events.next().await {
        match event {
            ServerEvent::TransportFailure { error, .. } => {
                println!("server: a write failed: {error}")
            }
            ServerEvent::Terminated => {
                println!("server: {} transaction terminated", flow.transport)
            }
            other => println!("server: {other:?}"),
        }
    }
}

/// RFC 3261's timers, or T1 from `--t1-ms` with T2 and T4 scaled alike.
fn timers_from_args() -> Result<Timers, BoxError> {
    let mut args = env::args().skip(1);
    let Some(flag) = args.next() else { return Ok(Timers::default()) };
    let ms: u64 = match (flag.as_str(), args.next()) {
        ("--t1-ms", Some(ms)) => ms.parse()?,
        _ => return Err("usage: options [--t1-ms MS]".into()),
    };
    Ok(Timers::builder()
        .t1(Duration::from_millis(ms))
        .t2(Duration::from_millis(ms * 8))
        .t4(Duration::from_millis(ms * 10))
        .build()?)
}
