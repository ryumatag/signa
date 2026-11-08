/*!
Two transaction-user loops on the loopback. The server answers OPTIONS over
UDP and TCP, with explicit client response observation.
*/

use bytes::Bytes;
use signa::{
    endpoint::{Endpoint, IncomingEvent, Target},
    message::header::Tag,
    transport::Transport,
    Request, Response,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (server, mut incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse()?)
        .tcp("127.0.0.1:0".parse()?)
        .bind()?;
    let serving = tokio::spawn(async move {
        while let Some(event) = incoming.recv().await {
            if let IncomingEvent::Request(envelope) = event {
                println!(
                    "server: {} from {} over {}",
                    envelope.request.method(),
                    envelope.flow.remote,
                    envelope.flow.transport
                );
                let (responder, _) = envelope.transaction.into_parts();
                let response = Response::reply_to(&envelope.request)
                    .status(200)
                    .header("Allow", "OPTIONS")
                    .to_tag(Tag::random())
                    .body(Bytes::new())
                    .expect("valid response");

                responder.respond(response).await.expect("accepted response");
            }
        }
    });

    let (client_end, _client_incoming) =
        Endpoint::builder().udp("127.0.0.1:0".parse()?).bind()?;

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
            client_end.start(request, target).await?.into_parts();
        let mut response =
            responses.next().await.expect("transaction outcome")?;
        while response.status().as_u16() < 200 {
            response = responses.next().await.expect("final outcome")?;
        }
        println!("client: {} over {transport}", response.status());
    }

    serving.abort();
    let _ = serving.await;
    Ok(())
}
