### Serving requests

A UAS for non-INVITE requests receives owned transaction-user envelopes. The
application chooses its To tag, submits a response, and can observe the
transaction separately. `to_tag` adds a fresh tag to an initial request's
response and keeps the tag of a request within a dialog. A failed submission is
logged rather than returned, since leaving the loop would drop `incoming` and
shut the endpoint down.

```no_run
use bytes::Bytes;
use signa::{
    endpoint::{Endpoint, IncomingEvent},
    message::header::Tag,
    Method, Response,
};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let (_endpoint, mut incoming) = Endpoint::builder()
    .udp("0.0.0.0:5060".parse()?)
    .tcp("0.0.0.0:5060".parse()?)
    .bind()?;

while let Some(event) = incoming.recv().await {
    if let IncomingEvent::Request(envelope) = event {
        // A 2xx to an INVITE starts a dialog, whose 2xx retransmissions and
        // ACK this loop does not handle.
        let status = if envelope.request.method() == Method::INVITE {
            501
        } else {
            200
        };
        let (responder, _) = envelope.transaction.into_parts();
        let response = Response::reply_to(&envelope.request)
            .status(status)
            .to_tag(Tag::random())
            .body(Bytes::new())?;

        if let Err(error) = responder.respond(response).await {
            eprintln!("response not accepted: {error}");
        }
    }
}
# Ok(())
# }
```

### Sending a request

An explicit target chooses the next hop. The endpoint adds a fresh Via and
returns a transaction after acceptance. Its response stream exposes provisional
responses followed by the final response or a terminal error.

```no_run
use bytes::Bytes;
use signa::{endpoint::{Endpoint, Target}, transport::Transport, Request};

# async fn run(endpoint: Endpoint) -> Result<(), Box<dyn std::error::Error>> {
let target = Target::new(Transport::Udp, "192.0.2.4:5060".parse()?);
let request = Request::builder()
    .method("OPTIONS")
    .uri("sip:bob@192.0.2.4")
    .header("From", "<sip:alice@192.0.2.1>;tag=1928301774")
    .header("To", "<sip:bob@192.0.2.4>")
    .header("Call-ID", "a84b4c76e66710")
    .header("CSeq", "1 OPTIONS")
    .header("Max-Forwards", "70")
    .body(Bytes::new())?;

let (control, mut responses) =
    endpoint.start(request, target).await?.into_parts();
println!("local address: {}", control.flow().local);
while let Some(response) = responses.next().await {
    let response = response?;
    println!("{}", response.status());
}
# Ok(())
# }
```
