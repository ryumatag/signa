/*!
INVITE transactions, [RFC 3261 section 17] as amended by [RFC 6026].

The driver matches input before calling these machines, sends returned bytes
on the transaction's original next hop or reply route, and delivers TU events.
It processes due timers before input at the same instant. In particular, a
response arriving at B or M cannot revive a transaction that has expired. The
caller supplies monotonically increasing instants and unchanged timers.

These machines do not create CANCEL transactions or generate 2xx ACKs. The
endpoint's cancellation intent and the TU own those operations.

[RFC 3261 section 17]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17
[RFC 6026]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8
*/

pub use self::{
    client::{ClientEvent, ClientTransaction, InvalidInvite},
    server::{ResponseError, ServerEvent, ServerTransaction},
};

mod client;
mod server;

#[cfg(test)]
mod tests {

    use crate::message::{
        header::{HeaderValue, TO},
        Request, Response,
    };
    use bytes::Bytes;
    use std::time::Duration;

    pub(super) const INVITE: &[u8] = b"\
INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP atlanta.example.com:5060;branch=z9hG4bKfirst;x=\"a,b\", SIP/2.0/UDP older.example.com;branch=z9hG4bKsecond\r\n\
Via: SIP/2.0/UDP oldest.example.com;branch=z9hG4bKthird\r\n\
From: Alice <sip:alice@atlanta.example.com>;tag=alice\r\n\
To: Bob <sip:bob@biloxi.example.com>\r\n\
Call-ID: call@atlanta.example.com\r\n\
CSeq: 314159 INVITE\r\n\
Max-Forwards: 65\r\n\
Route: <sip:first.example.com;lr>, <sip:second.example.com;lr>\r\n\
Route: <sip:third.example.com;lr>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 4\r\n\r\nbody";

    pub(super) const T1: Duration = Duration::from_millis(500);
    pub(super) const TIMERS: crate::transaction::Timers =
        crate::transaction::Timers::new();

    pub(super) fn request() -> Request<Bytes> {
        Request::from_bytes(INVITE).unwrap()
    }

    pub(super) fn response(code: u16, tag: &str) -> Response<Bytes> {
        Response::reply_to(&request())
            .status(code)
            .body(Bytes::new())
            .map(|mut response| {
                response.headers_mut().insert(
                    TO,
                    HeaderValue::from_bytes(
                        format!("Bob <sip:bob@biloxi.example.com>;tag={tag}")
                            .as_bytes(),
                    )
                    .unwrap(),
                );
                response
            })
            .unwrap()
    }
}
