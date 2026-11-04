/*!
A SIP message that is either a request or a response.
*/

use bytes::{Bytes, BytesMut};

use crate::{error::InvalidMessage, request::Request, response::Response};

/// A SIP request or response.
///
/// UDP sockets and TCP connections carry both kinds, so a received message
/// may be either. [`Message::from_shared`] parses the head once and decides
/// from its start-line.
///
/// ```
/// use bytes::Bytes;
/// use signa::{Message, StatusCode};
///
/// let datagram = Bytes::from_static(b"SIP/2.0 180 Ringing\r\n\r\n");
///
/// match Message::from_shared(datagram)? {
///     Message::Request(request) => println!("request {}", request.method()),
///     Message::Response(response) => {
///         assert_eq!(response.status(), StatusCode::RINGING);
///     }
/// }
/// # Ok::<(), signa::error::InvalidMessage>(())
/// ```
#[derive(Clone, Debug)]
pub enum Message<T> {
    /// A request.
    Request(Request<T>),
    /// A response.
    Response(Response<T>),
}

impl Message<Bytes> {
    /// Parses a request or response from the bytes of one complete message,
    /// copying them.
    ///
    /// This is [`Message::from_shared`] on a copy of `src`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMessage`] in the same cases as
    /// [`Message::from_shared`].
    pub fn from_bytes(src: &[u8]) -> Result<Message<Bytes>, InvalidMessage> {
        Message::from_shared(Bytes::copy_from_slice(src))
    }

    /// Parses a request or response from the bytes of one complete message
    /// without copying them.
    ///
    /// A start-line that begins with `SIP/` is a status-line, and anything
    /// else is a request-line. The message is then parsed like
    /// [`Request::from_shared`] or [`Response::from_shared`].
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMessage`] in the same cases as
    /// [`Request::from_shared`] or [`Response::from_shared`], whichever
    /// matches the start-line.
    pub fn from_shared(src: Bytes) -> Result<Message<Bytes>, InvalidMessage> {
        crate::parse::message(src)
    }
}

impl<T: AsRef<[u8]>> Message<T> {
    /// Writes the message to the end of `dst`.
    ///
    /// This is [`Request::encode`] or [`Response::encode`], whichever the
    /// message holds.
    pub fn encode(&self, dst: &mut BytesMut) {
        match self {
            Message::Request(request) => request.encode(dst),
            Message::Response(response) => response.encode(dst),
        }
    }

    /// Returns the message as bytes.
    ///
    /// This is [`Message::encode`] into a new buffer.
    pub fn to_bytes(&self) -> Bytes {
        let mut dst = BytesMut::new();
        self.encode(&mut dst);
        dst.freeze()
    }
}
