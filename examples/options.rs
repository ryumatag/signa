/*!
Two endpoints on the loopback. One answers every request with a 200, and the
other sends it an `OPTIONS` over UDP and over TCP and prints what came back.

Run it with `cargo run --example options`.
*/

use std::convert::Infallible;

use bytes::Bytes;
use signa::{
    endpoint::{Endpoint, Flow, Transport},
    Request, Response, StatusCode,
};
use tower_service::Service;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The server. Port 0 lets the OS pick, which keeps this example from
    // colliding with a real SIP element on 5060.
    let server = Endpoint::builder()
        .udp("127.0.0.1:0".parse()?)
        .tcp("127.0.0.1:0".parse()?)
        .serve(tower::service_fn(|request: Request<Bytes>| async move {
            // The endpoint put the flow the request arrived on into the
            // extensions, so a service can see where it came from.
            let flow = request.extensions().get::<Flow>().expect("a flow");
            println!(
                "server: {} from {} over {}",
                request.method(),
                flow.remote,
                flow.transport
            );
            // `reply_to` copies the header fields every response has to
            // carry, among them the `Via` the endpoint routes it by.
            let response = Response::reply_to(&request)
                .status(StatusCode::OK)
                .header("Allow", "OPTIONS")
                .body(Bytes::new())
                .expect("the status is set");
            Ok::<_, Infallible>(response)
        }))?;

    // The client side is an endpoint too, since SIP sends and receives on the
    // same socket. It needs no service of its own beyond one that refuses.
    let client_end = Endpoint::builder().udp("127.0.0.1:0".parse()?).serve(
        tower::service_fn(|request: Request<Bytes>| async move {
            Ok::<_, Infallible>(
                Response::reply_to(&request)
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Bytes::new())
                    .expect("the status is set"),
            )
        }),
    )?;

    let hops = [
        (Transport::Udp, server.udp_addr().expect("bound")),
        (Transport::Tcp, server.tcp_addr().expect("bound")),
    ];
    for (transport, next_hop) in hops {
        let mut client = client_end.client(transport, next_hop);
        let request = Request::builder()
            .method("OPTIONS")
            .uri(format!("sip:bob@{next_hop}").as_str())
            .header("From", "<sip:alice@127.0.0.1>;tag=1928301774")
            .header("To", "<sip:bob@127.0.0.1>")
            .header("Call-ID", format!("a84b4c76e66710-{transport}").as_str())
            .header("CSeq", "1 OPTIONS")
            .header("Max-Forwards", "70")
            .body(Bytes::new())?;

        let response = client.call(request).await?;
        println!(
            "client: {} {} over {transport}, Allow: {}",
            response.status(),
            response.status().canonical_reason().unwrap_or(""),
            response.headers().get("Allow").map_or("", |v| v.as_str())
        );
    }

    Ok(())
}
