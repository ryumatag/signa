/*!
Splitting a byte stream into SIP messages and keepalives.

On a stream transport such as TCP, a message ends where its `Content-Length`
says, which RFC 3261 sections 18.3 and 20.14 require there. A head without it,
or one that siparse rejects, loses the framing for good, because nothing marks
where the next message starts. The decoder then returns an error and the
connection has to close.

The decoder is sans-IO. It takes the buffer a transport reads into and returns
one frame at a time, so tests feed it bytes by hand and the transport decides
how to read and when to close.
*/

use std::{error, fmt, mem};

use bytes::{Buf, Bytes, BytesMut};
use siparse::{Status, find_head_end, parse_ping, parse_pong};

use super::MessageLimits;
use crate::message::{
    Message,
    error::{InvalidMessage, InvalidMessageKind},
    parse::{self, Head},
};

/// Splits a byte stream into messages and RFC 5626 keepalives.
///
/// Call [`Decoder::decode`] with the read buffer after each read. It returns
/// a frame and takes its bytes out of the buffer, or `None` when the buffer
/// ends before the next frame does. Call it again until it returns `None`
/// before reading more, since one read can carry several frames.
///
/// After an error, the connection must close. The decoder keeps no position
/// to resume from, because the stream has no way to find the next message.
#[derive(Debug)]
pub struct Decoder {
    role: Role,
    limits: MessageLimits,
    state: State,
}

/// Which end of the connection a decoder is on.
///
/// RFC 5626 keepalives go one way. The side that opened the connection sends
/// a double `CRLF` ping, and the side that accepted it answers with a single
/// `CRLF` pong. So a lone `CRLF` at a message boundary is half a ping on the
/// accepting side, which waits for the rest, and a pong on the opening side,
/// which must not wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// This end opened the connection and may receive pongs.
    Client,
    /// This end accepted the connection and may receive pings.
    Server,
}

/// One item from the stream.
#[derive(Debug)]
pub enum Frame {
    /// A request or response.
    Message(Message<Bytes>),
    /// An RFC 5626 ping. The transport answers it with a single `CRLF`.
    Ping,
    /// An RFC 5626 pong, the answer to a ping the transport sent.
    Pong,
}

/// Why a decoder gave up on a connection.
#[derive(Debug)]
pub enum DecodeError {
    /// The head or the `Content-Length` is invalid.
    Invalid(InvalidMessage),
    /// The head has no `Content-Length`, which a stream needs to find the end
    /// of the body.
    MissingContentLength,
    /// The head is larger than [`MessageLimits::head`] allows.
    HeadTooLarge,
    /// The body is larger than [`MessageLimits::body`] allows.
    BodyTooLarge,
}

#[derive(Debug)]
enum State {
    /// Looking for the end of the next head.
    ///
    /// `scanned` is how far the buffer has been searched for it, so the next
    /// search skips that much. It is zero at a message boundary, where
    /// keepalives are checked for first.
    Head { scanned: usize },
    /// The head is parsed. Waiting for `len` bytes of body.
    Body { head: Head, len: usize },
}

impl Decoder {
    /// Creates a decoder for one connection.
    pub fn new(role: Role, limits: MessageLimits) -> Decoder {
        Decoder { role, limits, state: State::Head { scanned: 0 } }
    }

    /// Returns the next frame from the start of `buf`, taking its bytes out
    /// of the buffer, or `None` if the buffer ends before the frame does.
    ///
    /// The buffer must only grow between calls. The decoder remembers how
    /// much of it has been searched already, so a head that arrives in many
    /// small reads costs time linear in its length. Only the body may wait
    /// in the buffer after its head is parsed.
    ///
    /// # Errors
    ///
    /// Returns an error for a head that is invalid, has no `Content-Length`,
    /// or is larger than the limits allow. See [`DecodeError`]. The connection
    /// must close after an error.
    pub fn decode(
        &mut self,
        buf: &mut BytesMut,
    ) -> Result<Option<Frame>, DecodeError> {
        loop {
            match &mut self.state {
                State::Head { scanned } => {
                    if *scanned == 0 {
                        match keepalive(self.role, buf) {
                            Status::Complete(Some((frame, len))) => {
                                buf.advance(len);
                                return Ok(Some(frame));
                            }
                            Status::Complete(None) => {}
                            Status::Partial => return Ok(None),
                        }
                    }

                    // The buffer only grows between calls, so `scanned` is at
                    // most its length. The `min` keeps a misuse from panicking
                    // inside siparse.
                    let searched = (*scanned).min(buf.len());
                    let Some(head_end) = find_head_end(buf, searched) else {
                        if buf.len() > self.limits.head {
                            return Err(DecodeError::HeadTooLarge);
                        }
                        *scanned = buf.len();
                        return Ok(None);
                    };
                    if head_end > self.limits.head {
                        return Err(DecodeError::HeadTooLarge);
                    }

                    // The head is frozen first, so the parts can share it.
                    let head = buf.split_to(head_end).freeze();
                    let head = match parse::head(&head)? {
                        Status::Complete((head, end)) => {
                            debug_assert_eq!(end, head_end);
                            head
                        }
                        // The empty line that `find_head_end` found ends a
                        // head unless it is all `CRLF`s, and the keepalive
                        // check above has taken those. This arm is a guard
                        // against that reasoning being wrong, not a path
                        // that input can reach.
                        Status::Partial => {
                            return Err(DecodeError::Invalid(
                                InvalidMessage::new(
                                    InvalidMessageKind::IncompleteHead,
                                ),
                            ));
                        }
                    };

                    let len = parse::content_length(head.headers())?
                        .ok_or(DecodeError::MissingContentLength)?;
                    if len > self.limits.body {
                        return Err(DecodeError::BodyTooLarge);
                    }
                    self.state = State::Body { head, len };
                }
                State::Body { len, .. } => {
                    if buf.len() < *len {
                        return Ok(None);
                    }
                    let next = State::Head { scanned: 0 };
                    let State::Body { head, len } =
                        mem::replace(&mut self.state, next)
                    else {
                        unreachable!("the state was checked above");
                    };
                    let body = buf.split_to(len).freeze();
                    return Ok(Some(Frame::Message(head.into_message(body))));
                }
            }
        }
    }
}

/// Checks for the keepalive this role may receive at a message boundary.
///
/// Returns the frame and its length, `None` if `buf` starts with something
/// else, or `Partial` if `buf` is a proper prefix of the keepalive.
fn keepalive(role: Role, buf: &[u8]) -> Status<Option<(Frame, usize)>> {
    let (status, frame) = match role {
        Role::Server => (parse_ping(buf), Frame::Ping),
        Role::Client => (parse_pong(buf), Frame::Pong),
    };
    match status {
        Status::Complete(Some(len)) => Status::Complete(Some((frame, len))),
        Status::Complete(None) => Status::Complete(None),
        Status::Partial => Status::Partial,
    }
}

impl From<InvalidMessage> for DecodeError {
    fn from(err: InvalidMessage) -> DecodeError {
        DecodeError::Invalid(err)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Invalid(err) => fmt::Display::fmt(err, f),
            DecodeError::MissingContentLength => {
                f.write_str("SIP message on a stream has no Content-Length")
            }
            DecodeError::HeadTooLarge => {
                f.write_str("SIP message head exceeds the size limit")
            }
            DecodeError::BodyTooLarge => {
                f.write_str("SIP message body exceeds the size limit")
            }
        }
    }
}

impl error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DecodeError::Invalid(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{
        Method, StatusCode,
        header::{CALL_ID, VIA},
    };

    const INVITE: &[u8] = b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
        Via: SIP/2.0/TCP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n\
        Call-ID: a84b4c76e66710\r\n\
        CSeq: 314159 INVITE\r\n\
        Content-Type: application/sdp\r\n\
        Content-Length: 8\r\n\
        \r\n\
        v=0\r\nt=0";

    const RINGING: &[u8] = b"SIP/2.0 180 Ringing\r\n\
        Call-ID: a84b4c76e66710\r\n\
        Content-Length: 0\r\n\
        \r\n";

    const NO_LENGTH: &[u8] = b"OPTIONS sip:bob@biloxi.example.com SIP/2.0\r\n\
        Call-ID: a84b4c76e66710\r\n\
        \r\n";

    fn decoder(role: Role) -> Decoder {
        Decoder::new(role, MessageLimits::default())
    }

    /// Decodes every frame in `buf` with a fresh decoder.
    fn decode_all(role: Role, buf: &mut BytesMut) -> Vec<Frame> {
        let mut decoder = decoder(role);
        let mut frames = Vec::new();
        while let Some(frame) = decoder.decode(buf).unwrap() {
            frames.push(frame);
        }
        frames
    }

    /// Feeds `input` in reads of `read` bytes and returns every frame.
    fn decode_in_reads(role: Role, input: &[u8], read: usize) -> Vec<Frame> {
        let mut decoder = decoder(role);
        let mut buf = BytesMut::new();
        let mut frames = Vec::new();
        for chunk in input.chunks(read) {
            buf.extend_from_slice(chunk);
            while let Some(frame) = decoder.decode(&mut buf).unwrap() {
                frames.push(frame);
            }
        }
        assert!(buf.is_empty(), "read={read}");
        frames
    }

    fn describe(frame: &Frame) -> String {
        match frame {
            Frame::Message(Message::Request(request)) => format!(
                "{} {} {:?}",
                request.method(),
                request.headers().len(),
                request.body()
            ),
            Frame::Message(Message::Response(response)) => format!(
                "{} {} {:?}",
                response.status(),
                response.headers().len(),
                response.body()
            ),
            Frame::Ping => "ping".to_owned(),
            Frame::Pong => "pong".to_owned(),
        }
    }

    fn decode_err(role: Role, input: &[u8]) -> DecodeError {
        let mut decoder = decoder(role);
        let mut buf = BytesMut::from(input);
        loop {
            match decoder.decode(&mut buf) {
                Ok(Some(_)) => {}
                Ok(None) => panic!("expected an error, got None"),
                Err(err) => return err,
            }
        }
    }

    #[test]
    fn decodes_a_request_and_a_response() {
        let mut buf = BytesMut::from(INVITE);
        let frames = decode_all(Role::Server, &mut buf);
        let [Frame::Message(Message::Request(request))] = &frames[..] else {
            panic!("{frames:?}");
        };
        assert_eq!(request.method(), Method::INVITE);
        assert_eq!(request.headers().get(CALL_ID).unwrap(), "a84b4c76e66710");
        assert_eq!(request.body(), "v=0\r\nt=0");
        assert!(buf.is_empty());

        let mut buf = BytesMut::from(RINGING);
        let frames = decode_all(Role::Client, &mut buf);
        let [Frame::Message(Message::Response(response))] = &frames[..] else {
            panic!("{frames:?}");
        };
        assert_eq!(response.status(), StatusCode::RINGING);
        assert!(response.body().is_empty());
        assert!(buf.is_empty());
    }

    #[test]
    fn shares_the_read_buffer_instead_of_copying() {
        let mut buf = BytesMut::from(INVITE);
        let range = buf.as_ptr_range();
        let within = |bytes: &[u8]| range.contains(&bytes.as_ptr());

        let frames = decode_all(Role::Server, &mut buf);
        let [Frame::Message(Message::Request(request))] = &frames[..] else {
            panic!("{frames:?}");
        };
        assert!(within(request.uri().as_str().as_bytes()));
        assert!(within(request.headers().get(VIA).unwrap().as_bytes()));
        assert!(within(request.body()));
    }

    #[test]
    fn decodes_pipelined_messages_and_keeps_the_rest() {
        let mut input = INVITE.to_vec();
        input.extend_from_slice(RINGING);
        input.extend_from_slice(INVITE);
        input.extend_from_slice(&RINGING[..10]);
        let mut buf = BytesMut::from(&input[..]);

        let frames = decode_all(Role::Server, &mut buf);
        let described: Vec<_> = frames.iter().map(describe).collect();
        assert_eq!(
            described,
            [
                "INVITE 5 b\"v=0\\r\\nt=0\"",
                "180 2 b\"\"",
                "INVITE 5 b\"v=0\\r\\nt=0\"",
            ]
        );
        assert_eq!(&buf[..], &RINGING[..10]);
    }

    /// The frames must not depend on how the bytes are split into reads.
    #[test]
    fn every_read_size_gives_the_same_frames() {
        let mut input = b"\r\n\r\n".to_vec();
        input.extend_from_slice(INVITE);
        input.extend_from_slice(b"\r\n\r\n\r\n\r\n");
        input.extend_from_slice(RINGING);
        input.extend_from_slice(
            b"\r\nINVITE sip:a@b SIP/2.0\r\nl: 2\r\n\r\nhi",
        );

        let whole: Vec<_> = decode_in_reads(Role::Server, &input, input.len())
            .iter()
            .map(describe)
            .collect();
        assert_eq!(
            whole,
            [
                "ping",
                "INVITE 5 b\"v=0\\r\\nt=0\"",
                "ping",
                "ping",
                "180 2 b\"\"",
                "INVITE 1 b\"hi\"",
            ]
        );

        for read in 1..input.len() {
            let frames: Vec<_> = decode_in_reads(Role::Server, &input, read)
                .iter()
                .map(describe)
                .collect();
            assert_eq!(frames, whole, "read={read}");
        }
    }

    #[test]
    fn waits_for_the_body_after_the_head() {
        let head_len = INVITE.len() - 8;
        let mut decoder = decoder(Role::Server);
        let mut buf = BytesMut::from(&INVITE[..head_len + 3]);

        assert!(decoder.decode(&mut buf).unwrap().is_none());
        // The head is gone from the buffer, and the decoder holds it.
        assert_eq!(&buf[..], &INVITE[head_len..head_len + 3]);
        assert!(matches!(decoder.state, State::Body { len: 8, .. }));

        buf.extend_from_slice(&INVITE[head_len + 3..]);
        let frame = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(describe(&frame), "INVITE 5 b\"v=0\\r\\nt=0\"");
        assert!(buf.is_empty());
    }

    #[test]
    fn searches_only_new_bytes_for_the_end_of_the_head() {
        let mut decoder = decoder(Role::Server);
        let mut buf = BytesMut::from(&INVITE[..20]);

        assert!(decoder.decode(&mut buf).unwrap().is_none());
        assert!(matches!(decoder.state, State::Head { scanned: 20 }));

        buf.extend_from_slice(&INVITE[20..50]);
        assert!(decoder.decode(&mut buf).unwrap().is_none());
        assert!(matches!(decoder.state, State::Head { scanned: 50 }));
    }

    #[test]
    fn server_answers_pings_and_waits_for_half_of_one() {
        let mut decoder = decoder(Role::Server);
        let mut buf = BytesMut::from(&b"\r\n\r\n\r\n"[..]);

        assert!(matches!(
            decoder.decode(&mut buf).unwrap(),
            Some(Frame::Ping)
        ));
        assert_eq!(&buf[..], b"\r\n");
        assert!(decoder.decode(&mut buf).unwrap().is_none());
        assert_eq!(&buf[..], b"\r\n");

        buf.extend_from_slice(b"\r\n");
        assert!(matches!(
            decoder.decode(&mut buf).unwrap(),
            Some(Frame::Ping)
        ));
        assert!(buf.is_empty());
    }

    #[test]
    fn client_takes_each_crlf_as_a_pong() {
        let mut decoder = decoder(Role::Client);
        let mut buf = BytesMut::from(&b"\r\n\r\n\r"[..]);

        assert!(matches!(
            decoder.decode(&mut buf).unwrap(),
            Some(Frame::Pong)
        ));
        assert!(matches!(
            decoder.decode(&mut buf).unwrap(),
            Some(Frame::Pong)
        ));
        assert!(decoder.decode(&mut buf).unwrap().is_none());
        assert_eq!(&buf[..], b"\r");

        buf.extend_from_slice(b"\n");
        buf.extend_from_slice(RINGING);
        assert!(matches!(
            decoder.decode(&mut buf).unwrap(),
            Some(Frame::Pong)
        ));
        let frame = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(describe(&frame), "180 2 b\"\"");
    }

    #[test]
    fn skips_a_lone_crlf_before_a_head() {
        // RFC 3261 section 7.5. Not a keepalive on the server side, since a
        // ping is two of them.
        let mut input = b"\r\n".to_vec();
        input.extend_from_slice(RINGING);
        let mut buf = BytesMut::from(&input[..]);

        let frames = decode_all(Role::Server, &mut buf);
        assert_eq!(frames.len(), 1);
        assert_eq!(describe(&frames[0]), "180 2 b\"\"");
        assert!(buf.is_empty());
    }

    #[test]
    fn rejects_a_head_without_content_length() {
        assert!(matches!(
            decode_err(Role::Server, NO_LENGTH),
            DecodeError::MissingContentLength
        ));
    }

    #[test]
    fn rejects_an_invalid_head_or_content_length() {
        let err = decode_err(
            Role::Server,
            b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\nCall ID: x\r\n\r\n",
        );
        assert!(matches!(err, DecodeError::Invalid(_)));
        assert_eq!(err.to_string(), "missing colon after SIP header name");
        assert!(error::Error::source(&err).is_some());

        let err = decode_err(
            Role::Server,
            b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\nl: x\r\n\r\n",
        );
        assert_eq!(err.to_string(), "invalid Content-Length in SIP message");
    }

    /// A wrong `Content-Length` is not detected as such. The stream loses its
    /// framing, and the bytes after the claimed body fail as a head.
    #[test]
    fn a_short_content_length_loses_the_framing() {
        let mut input =
            b"MESSAGE sip:bob@biloxi.example.com SIP/2.0\r\nl: 2\r\n\r\nhello"
                .to_vec();
        input.extend_from_slice(RINGING);
        let mut decoder = decoder(Role::Server);
        let mut buf = BytesMut::from(&input[..]);

        let frame = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(describe(&frame), "MESSAGE 1 b\"he\"");
        let err = decoder.decode(&mut buf).unwrap_err();
        assert!(matches!(err, DecodeError::Invalid(_)), "{err}");
    }

    #[test]
    fn limits_the_head_size() {
        let limits = MessageLimits { head: RINGING.len(), body: 0 };

        let mut decoder = Decoder::new(Role::Server, limits);
        let mut buf = BytesMut::from(RINGING);
        assert!(decoder.decode(&mut buf).unwrap().is_some());

        // One byte over, whether the end has arrived or not.
        let mut input = b"\r\n".to_vec();
        input.extend_from_slice(RINGING);
        let mut decoder = Decoder::new(Role::Server, limits);
        let mut buf = BytesMut::from(&input[..input.len() - 2]);
        assert!(decoder.decode(&mut buf).unwrap().is_none());
        buf.extend_from_slice(b"\r");
        let err = decoder.decode(&mut buf).unwrap_err();
        assert!(matches!(err, DecodeError::HeadTooLarge), "{err}");

        let mut decoder = Decoder::new(Role::Server, limits);
        let mut buf = BytesMut::from(&input[..]);
        let err = decoder.decode(&mut buf).unwrap_err();
        assert!(matches!(err, DecodeError::HeadTooLarge), "{err}");
    }

    #[test]
    fn limits_the_body_size() {
        let limits = MessageLimits { head: usize::MAX, body: 7 };
        let mut decoder = Decoder::new(Role::Server, limits);
        let mut buf = BytesMut::from(&INVITE[..INVITE.len() - 8]);

        let err = decoder.decode(&mut buf).unwrap_err();
        assert!(matches!(err, DecodeError::BodyTooLarge), "{err}");
        assert_eq!(err.to_string(), "SIP message body exceeds the size limit");
    }

    #[test]
    fn tolerates_a_buffer_that_shrank() {
        let mut decoder = decoder(Role::Server);
        let mut buf = BytesMut::from(&INVITE[..30]);
        assert!(decoder.decode(&mut buf).unwrap().is_none());

        buf.clear();
        assert!(decoder.decode(&mut buf).unwrap().is_none());
    }
}
