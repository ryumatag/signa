/*!
What more than one module of the tests uses.
*/

use std::time::Duration;

use signa_core::endpoint::{Incoming, IncomingEvent, ServerRequest};
use tokio::time::timeout;

pub(crate) async fn request(incoming: &mut Incoming) -> ServerRequest {
    let event = timeout(Duration::from_secs(2), incoming.recv()).await;
    match event.unwrap().unwrap() {
        IncomingEvent::Request(request) => request,
        other => panic!("expected a request, got {other:?}"),
    }
}
