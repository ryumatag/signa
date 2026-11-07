/*!
Two transaction-user loops on the loopback. The server answers OPTIONS over
UDP and TCP. Client operations retain the Service API until their TU migration.
*/

use bytes::Bytes;
use signa::{
    endpoint::{Endpoint, IncomingEvent},
    message::header::Tag,
    transport::Transport,
    Request, Response,
};
use tower_service::Service;

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
        let mut client = client_end.client(transport, next_hop);
        let request = Request::builder()
            .method("OPTIONS")
            .uri(format!("sip:bob@{next_hop}").as_str())
            .header("From", "<sip:alice@127.0.0.1>;tag=alice")
            .header("To", "<sip:bob@127.0.0.1>")
            .header("Call-ID", format!("example-{transport}").as_str())
            .header("CSeq", "1 OPTIONS")
            .body(Bytes::new())?;

        let response = client.call(request).await?;
        println!("client: {} over {transport}", response.status());
    }

    serving.abort();
    let _ = serving.await;
    Ok(())
}
