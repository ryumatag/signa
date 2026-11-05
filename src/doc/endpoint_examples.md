### Serving requests

A UAS that answers every request with a 200. The service gets the request with
the [`Flow`](endpoint::Flow) it arrived on in its extensions, and
[`Response::reply_to`] starts the response with the header fields the
[`Endpoint`](endpoint::Endpoint) routes it by.

```no_run
use std::convert::Infallible;

use bytes::Bytes;
use signa::{endpoint::Endpoint, Request, Response, StatusCode};

# async fn run() -> std::io::Result<()> {
let endpoint = Endpoint::builder()
    .udp("0.0.0.0:5060".parse().unwrap())
    .tcp("0.0.0.0:5060".parse().unwrap())
    .serve(tower::service_fn(|request: Request<Bytes>| async move {
        let response = Response::reply_to(&request)
            .status(StatusCode::OK)
            .body(Bytes::new())
            .expect("the status is set");
        Ok::<_, Infallible>(response)
    }))?;

// The endpoint runs as long as a handle to it exists.
std::future::pending::<()>().await;
# drop(endpoint);
# Ok(())
# }
```

### Sending a request

A [`Client`](endpoint::Client) is bound to one next hop. The endpoint adds the
topmost `Via`, retransmits over UDP, and resolves the future with the final
response.

```no_run
use bytes::Bytes;
use signa::{endpoint::{Endpoint, Transport}, Request, StatusCode};
use tower_service::Service;

# async fn run(endpoint: Endpoint) -> Result<(), Box<dyn std::error::Error>> {
let mut client = endpoint.client(Transport::Udp, "192.0.2.4:5060".parse()?);
let request = Request::builder()
    .method("OPTIONS")
    .uri("sip:bob@192.0.2.4")
    .header("From", "<sip:alice@192.0.2.1>;tag=1928301774")
    .header("To", "<sip:bob@192.0.2.4>")
    .header("Call-ID", "a84b4c76e66710")
    .header("CSeq", "1 OPTIONS")
    .header("Max-Forwards", "70")
    .body(Bytes::new())?;

let response = client.call(request).await?;
assert_eq!(response.status(), StatusCode::OK);
# Ok(())
# }
```
