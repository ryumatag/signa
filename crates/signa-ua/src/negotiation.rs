/*!
Where an offer/answer exchange stands in one dialog, and which bodies take
part in it.

The model tracks which side owes an answer, and in which message, not what the
session descriptions say. SDP syntax and the legality of an answer are the job
of an external SDP component. What the UA keeps are the rules of SIP about
where offers and answers go:

* An INVITE with an offer gets the answer in its 2xx. One without gets an
  offer in the 2xx, and owes the answer in the ACK ([RFC 3261 section
  13.2.1]).
* An agent makes no new offer while one is unanswered in either direction
  ([RFC 3264 section 4]), so a dialog has at most one offer outstanding. Each
  offer belongs to the INVITE transaction that carried it, named by its CSeq
  number, and an answer for another one is refused.

A body is not a session description because it is there. [`Body::read`]
tells one by its Content-Disposition, or by its Content-Type when there is
none, as RFC 3261 section 20.11 sets the default, and never by the bytes.

[RFC 3261 section 13.2.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.1
[RFC 3264 section 4]: https://www.rfc-editor.org/rfc/rfc3264.html#section-4
*/

use std::fmt;

use bytes::Bytes;
use signa_core::{HeaderMap, HeaderValue, message::header::CONTENT_TYPE};

use crate::protocol::{self, Malformed};

/// A session description to carry in a message, such as the answer in a 2xx.
///
/// The UA does not look inside it. It goes out as the body, with
/// `content_type` as the Content-Type. Whether the bytes are a valid offer or
/// answer is for the code that made them to decide, such as an SDP
/// implementation.
///
/// Its `Debug` shows the Content-Type and the length of the body, not the
/// body. A session description can carry secrets: the SRTP keys of an
/// `a=crypto` line ([RFC 4568]) and the ICE password of `a=ice-pwd`
/// ([RFC 8839 section 5.4]). Read the body with [`Description::body`].
///
/// [RFC 4568]: https://www.rfc-editor.org/rfc/rfc4568.html
/// [RFC 8839 section 5.4]: https://www.rfc-editor.org/rfc/rfc8839.html#section-5.4
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
pub struct Description {
    content_type: HeaderValue,
    body: Bytes,
}

impl fmt::Debug for Description {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Description")
            .field("content_type", &self.content_type)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

// Only the runtime reads a description, to put it on the wire.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
impl Description {
    /// Creates a description of `body`, whose media type is
    /// `content_type`, such as `application/sdp`.
    #[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
    pub fn new(content_type: HeaderValue, body: Bytes) -> Description {
        Description { content_type, body }
    }

    /// Returns the media type of the body.
    #[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
    pub fn content_type(&self) -> &HeaderValue {
        &self.content_type
    }

    /// Returns the body.
    #[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Says whether the description needs `Content-Disposition: session`
    /// to be taken for one. Without that header, RFC 3261 section 20.11 makes
    /// only `application/sdp` a session description.
    pub(crate) fn needs_disposition(&self) -> bool {
        !protocol::media_type(self.content_type.as_str())
            .is_ok_and(|media| media.is("application", "sdp"))
    }
}

/// What the body of a message is to the offer/answer exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Body {
    /// There is none.
    Empty,
    /// A session description: an offer or an answer, by where it comes.
    Session(Description),
    /// A body that is something else, such as text to render. It takes no
    /// part in the exchange, and the UA leaves it to the application.
    Other,
    /// A body the UA cannot tell an offer or answer in: a multipart body,
    /// which may hold one among other parts, or a session description with
    /// a content coding. An INVITE with one gets a 415 (RFC 3261 section
    /// 8.2.3).
    ///
    /// TODO: Take a session description out of a multipart body, as RFC
    /// 5621 describes, for peers such as SIP-I gateways that send one.
    Unsupported,
    /// A session description larger than the UA keeps. An INVITE with one
    /// gets a 413 (RFC 3261 section 21.4.11).
    TooLarge,
}

impl Body {
    /// Reads the body of a message by its Content headers.
    ///
    /// A non-empty body without a Content-Type is malformed, since RFC 3261
    /// section 20.15 requires the header with any body. A body is a session
    /// description when its Content-Disposition says `session`, or when it
    /// has none and is `application/sdp`, the type section 20.11 gives that
    /// default. A multipart body without a disposition may hold one, so it is
    /// unsupported rather than other. The bytes are copied, so that a
    /// description the UA keeps does not hold on to the buffer the message
    /// arrived in. A description of more than `limit` bytes is not copied,
    /// since a session keeps the last one it got for as long as it lasts.
    pub(crate) fn read(
        headers: &HeaderMap,
        body: &[u8],
        limit: usize,
    ) -> Result<Body, Malformed> {
        if body.is_empty() {
            return Ok(Body::Empty);
        }
        let media = protocol::content_type(headers)?
            .ok_or(Malformed(protocol::Field::ContentType))?;
        let disposition = protocol::content_disposition(headers)?;

        let multipart = media.kind.eq_ignore_ascii_case("multipart");
        let session = match disposition {
            Some(kind) => kind.eq_ignore_ascii_case("session"),
            None if multipart => return Ok(Body::Unsupported),
            None => media.is("application", "sdp"),
        };
        if !session {
            return Ok(Body::Other);
        }
        if multipart || protocol::encoded(headers)? {
            return Ok(Body::Unsupported);
        }
        if body.len() > limit {
            return Ok(Body::TooLarge);
        }

        let content_type = headers.get(CONTENT_TYPE).expect("read above");
        Ok(Body::Session(Description {
            content_type: HeaderValue::from_bytes(content_type.as_bytes())
                .expect("a received value is valid"),
            body: Bytes::copy_from_slice(body),
        }))
    }

    /// Reads a body for the session description it may be, where nothing
    /// is answered for a body the UA cannot use, as in a response or an ACK.
    /// One larger than `limit` counts as none, which fails an exchange that
    /// needed it.
    // Only the runtime reads responses and ACKs.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn description(
        headers: &HeaderMap,
        body: &[u8],
        limit: usize,
    ) -> Option<Description> {
        match Body::read(headers, body, limit) {
            Ok(Body::Session(description)) => Some(description),
            _ => None,
        }
    }
}

/// The offer/answer state of one dialog.
///
/// An outstanding offer remembers the CSeq number of the INVITE whose
/// transaction carries it, so that an answer for another transaction cannot
/// settle it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Negotiation {
    /// No offer is outstanding.
    #[default]
    Stable,
    /// This user agent sent an offer and waits for the answer.
    LocalOfferOutstanding { cseq: u32 },
    /// The peer sent an offer and waits for this user agent's answer.
    RemoteOfferOutstanding { cseq: u32 },
}

/// An offer or answer the state does not allow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutOfOrder(pub(crate) Negotiation);

impl Negotiation {
    pub(crate) fn offer_sent(&mut self, cseq: u32) -> Result<(), OutOfOrder> {
        self.step(
            Negotiation::Stable,
            Negotiation::LocalOfferOutstanding { cseq },
        )
    }

    pub(crate) fn offer_received(
        &mut self,
        cseq: u32,
    ) -> Result<(), OutOfOrder> {
        self.step(
            Negotiation::Stable,
            Negotiation::RemoteOfferOutstanding { cseq },
        )
    }

    pub(crate) fn answer_sent(&mut self, cseq: u32) -> Result<(), OutOfOrder> {
        self.step(
            Negotiation::RemoteOfferOutstanding { cseq },
            Negotiation::Stable,
        )
    }

    pub(crate) fn answer_received(
        &mut self,
        cseq: u32,
    ) -> Result<(), OutOfOrder> {
        self.step(
            Negotiation::LocalOfferOutstanding { cseq },
            Negotiation::Stable,
        )
    }

    /// Says whether this user agent waits for the answer to the offer the
    /// transaction `cseq` carried.
    pub(crate) fn awaits_answer(&self, cseq: u32) -> bool {
        *self == Negotiation::LocalOfferOutstanding { cseq }
    }

    fn step(
        &mut self,
        from: Negotiation,
        to: Negotiation,
    ) -> Result<(), OutOfOrder> {
        if *self != from {
            return Err(OutOfOrder(*self));
        }

        *self = to;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use signa_core::message::header::{CONTENT_DISPOSITION, CONTENT_ENCODING};

    use super::*;

    #[test]
    fn offers_and_answers_alternate() {
        let mut state = Negotiation::Stable;

        state.offer_sent(1).unwrap();
        assert_eq!(state, Negotiation::LocalOfferOutstanding { cseq: 1 });
        assert!(state.awaits_answer(1));
        state.answer_received(1).unwrap();
        assert_eq!(state, Negotiation::Stable);

        state.offer_received(2).unwrap();
        assert_eq!(state, Negotiation::RemoteOfferOutstanding { cseq: 2 });
        state.answer_sent(2).unwrap();
        assert_eq!(state, Negotiation::Stable);
    }

    #[test]
    fn a_second_offer_waits_for_the_first_answer() {
        for outstanding in [
            Negotiation::LocalOfferOutstanding { cseq: 1 },
            Negotiation::RemoteOfferOutstanding { cseq: 1 },
        ] {
            let mut state = outstanding;

            assert_eq!(state.offer_sent(2), Err(OutOfOrder(outstanding)));
            assert_eq!(state.offer_received(2), Err(OutOfOrder(outstanding)));
            assert_eq!(state, outstanding);
        }
    }

    #[test]
    fn an_answer_needs_an_offer_from_the_other_side() {
        let mut state = Negotiation::LocalOfferOutstanding { cseq: 1 };

        assert!(state.answer_sent(1).is_err());
        assert!(Negotiation::Stable.answer_received(1).is_err());
        assert_eq!(state, Negotiation::LocalOfferOutstanding { cseq: 1 });
    }

    /// An offer outstanding in a dialog keeps a second one from starting,
    /// and an answer meant for another transaction of the dialog settles
    /// nothing.
    #[test]
    fn same_dialog_second_offer_is_not_started() {
        let mut state = Negotiation::Stable;
        state.offer_received(1).unwrap();

        assert!(state.offer_sent(2).is_err());
        assert!(state.offer_received(2).is_err());
        assert!(state.answer_sent(2).is_err());
        assert_eq!(state, Negotiation::RemoteOfferOutstanding { cseq: 1 });

        let mut sent = Negotiation::LocalOfferOutstanding { cseq: 1 };
        assert!(!sent.awaits_answer(2));
        assert!(sent.answer_received(2).is_err());
        assert_eq!(sent, Negotiation::LocalOfferOutstanding { cseq: 1 });
    }

    /// A limit no body of these tests reaches.
    const ANY: usize = usize::MAX;

    fn headers(rows: &[(signa_core::HeaderName, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in rows {
            headers.append(name.clone(), HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn a_description_needs_a_body_and_its_type() {
        let sdp = headers(&[(CONTENT_TYPE, "application/sdp")]);

        assert_eq!(Body::read(&sdp, b"", ANY), Ok(Body::Empty));
        assert!(Body::read(&headers(&[]), b"v=0\r\n", ANY).is_err());
        let Ok(Body::Session(description)) = Body::read(&sdp, b"v=0\r\n", ANY)
        else {
            panic!("an SDP body is a session description");
        };
        assert_eq!(description.content_type(), "application/sdp");
        assert_eq!(description.body().as_ref(), b"v=0\r\n");
    }

    /// Only the Content headers make a body a session description. The same
    /// bytes are one or not by what those headers say.
    #[test]
    fn body_bytes_alone_are_not_assumed_to_be_sdp() {
        let bytes = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\n";
        let cases = [
            (&[(CONTENT_TYPE, "text/plain")][..], Body::Other),
            (
                &[
                    (CONTENT_TYPE, "application/sdp"),
                    (CONTENT_DISPOSITION, "render"),
                ],
                Body::Other,
            ),
            (&[(CONTENT_TYPE, "multipart/mixed;boundary=x")], {
                Body::Unsupported
            }),
            (
                &[
                    (CONTENT_TYPE, "multipart/mixed;boundary=x"),
                    (CONTENT_DISPOSITION, "session"),
                ],
                Body::Unsupported,
            ),
            (
                &[
                    (CONTENT_TYPE, "application/sdp"),
                    (CONTENT_ENCODING, "gzip"),
                ],
                Body::Unsupported,
            ),
            (
                &[
                    (CONTENT_TYPE, "multipart/alternative;boundary=x"),
                    (CONTENT_DISPOSITION, "render;handling=optional"),
                ],
                Body::Other,
            ),
        ];

        for (rows, expected) in cases {
            assert_eq!(
                Body::read(&headers(rows), bytes, ANY),
                Ok(expected),
                "{rows:?}"
            );
        }

        for rows in [
            &[(CONTENT_TYPE, "Application/SDP")][..],
            &[
                (CONTENT_TYPE, "application/vnd.example"),
                (CONTENT_DISPOSITION, "session;handling=required"),
            ],
        ] {
            assert!(
                matches!(
                    Body::read(&headers(rows), bytes, ANY),
                    Ok(Body::Session(_))
                ),
                "{rows:?}",
            );
        }
    }

    /// A session description over the limit is not read, and only it. A
    /// body that is no description is the application's, whatever its size.
    #[test]
    fn a_description_over_the_limit_is_not_kept() {
        let sdp = headers(&[(CONTENT_TYPE, "application/sdp")]);
        let text = headers(&[(CONTENT_TYPE, "text/plain")]);

        assert!(matches!(
            Body::read(&sdp, b"v=0\r\n", 5),
            Ok(Body::Session(_))
        ));
        assert_eq!(Body::read(&sdp, b"v=0\r\n", 4), Ok(Body::TooLarge));
        assert_eq!(Body::read(&text, b"v=0\r\n", 4), Ok(Body::Other));
        assert_eq!(Body::description(&sdp, b"v=0\r\n", 4), None);
    }

    /// The body of a description can hold keys, so its `Debug` shows only
    /// how long it is.
    #[test]
    fn debug_leaves_the_body_out() {
        let description = Description::new(
            HeaderValue::from_static("application/sdp"),
            Bytes::from_static(
                b"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:key",
            ),
        );

        let shown = format!("{description:?}");
        assert!(!shown.contains("inline:key"), "{shown}");
        assert!(shown.contains("application/sdp") && shown.contains("45"));
    }

    #[test]
    fn only_sdp_goes_without_a_disposition() {
        let sdp = HeaderValue::from_static("application/sdp");
        let other = HeaderValue::from_static("application/vnd.example");

        assert!(!Description::new(sdp, Bytes::new()).needs_disposition());
        assert!(Description::new(other, Bytes::new()).needs_disposition());
    }
}
