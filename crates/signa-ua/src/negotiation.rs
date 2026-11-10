/*!
Where an offer/answer exchange stands in one dialog.

The model tracks which side owes an answer, not what the session
descriptions say. SDP syntax and the legality of an answer are the job of
an external SDP component. What the model keeps is the rule of
[RFC 3264 section 4] that an agent makes no new offer while one is
unanswered in either direction, so a dialog has at most one offer
outstanding. A second offer is refused here, before anything goes on
the wire.

TODO: Tie each offer to its exchange and generation, so that a late answer
for an earlier offer is refused as stale. Add the provider contract for the
answer an ACK must carry.

[RFC 3264 section 4]: https://www.rfc-editor.org/rfc/rfc3264.html#section-4
*/

use bytes::Bytes;
use signa_core::{HeaderMap, HeaderValue, message::header::CONTENT_TYPE};

/// A session description to carry in a message, such as the answer in a 2xx.
///
/// The UA does not look inside it. It goes out as the body, with
/// `content_type` as the Content-Type. Whether the bytes are a valid offer or
/// answer is for the code that made them to decide, such as an SDP
/// implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
pub struct Description {
    content_type: HeaderValue,
    body: Bytes,
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

    /// Reads the session description a message carries, its body with its
    /// Content-Type, or `None` without a body. A body without a Content-Type
    /// is not taken for one, since RFC 3261 section 20.15 requires the header
    /// with any body.
    ///
    /// Both are copied, so that a description the UA keeps does not hold on
    /// to the buffer the message arrived in.
    ///
    /// TODO: Tell a session description by its Content-Disposition too, and
    /// leave a multipart body to an adapter that can take it apart.
    pub(crate) fn from_message(
        headers: &HeaderMap,
        body: &[u8],
    ) -> Option<Description> {
        if body.is_empty() {
            return None;
        }
        let content_type = headers.get(CONTENT_TYPE)?;

        Some(Description {
            content_type: HeaderValue::from_bytes(content_type.as_bytes())
                .expect("a received value is valid"),
            body: Bytes::copy_from_slice(body),
        })
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
}

/// The offer/answer state of one dialog.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Negotiation {
    /// No offer is outstanding.
    #[default]
    Stable,
    /// This user agent sent an offer and waits for the answer.
    LocalOfferOutstanding,
    /// The peer sent an offer and waits for this user agent's answer.
    RemoteOfferOutstanding,
}

/// An offer or answer the state does not allow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutOfOrder(pub(crate) Negotiation);

impl Negotiation {
    pub(crate) fn offer_sent(&mut self) -> Result<(), OutOfOrder> {
        self.step(Negotiation::Stable, Negotiation::LocalOfferOutstanding)
    }

    pub(crate) fn offer_received(&mut self) -> Result<(), OutOfOrder> {
        self.step(Negotiation::Stable, Negotiation::RemoteOfferOutstanding)
    }

    pub(crate) fn answer_sent(&mut self) -> Result<(), OutOfOrder> {
        self.step(Negotiation::RemoteOfferOutstanding, Negotiation::Stable)
    }

    pub(crate) fn answer_received(&mut self) -> Result<(), OutOfOrder> {
        self.step(Negotiation::LocalOfferOutstanding, Negotiation::Stable)
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
    use super::*;

    #[test]
    fn offers_and_answers_alternate() {
        let mut state = Negotiation::Stable;

        state.offer_sent().unwrap();
        assert_eq!(state, Negotiation::LocalOfferOutstanding);
        state.answer_received().unwrap();
        assert_eq!(state, Negotiation::Stable);

        state.offer_received().unwrap();
        assert_eq!(state, Negotiation::RemoteOfferOutstanding);
        state.answer_sent().unwrap();
        assert_eq!(state, Negotiation::Stable);
    }

    #[test]
    fn a_second_offer_waits_for_the_first_answer() {
        for outstanding in [
            Negotiation::LocalOfferOutstanding,
            Negotiation::RemoteOfferOutstanding,
        ] {
            let mut state = outstanding;

            assert_eq!(state.offer_sent(), Err(OutOfOrder(outstanding)));
            assert_eq!(state.offer_received(), Err(OutOfOrder(outstanding)));
            assert_eq!(state, outstanding);
        }
    }

    #[test]
    fn an_answer_needs_an_offer_from_the_other_side() {
        let mut state = Negotiation::LocalOfferOutstanding;

        assert!(state.answer_sent().is_err());
        assert!(Negotiation::Stable.answer_received().is_err());
        assert_eq!(state, Negotiation::LocalOfferOutstanding);
    }

    #[test]
    fn a_description_needs_a_body_and_its_type() {
        let mut headers = HeaderMap::new();
        assert_eq!(Description::from_message(&headers, b"v=0\r\n"), None);

        headers
            .append(CONTENT_TYPE, HeaderValue::from_static("application/sdp"));
        assert_eq!(Description::from_message(&headers, b""), None);
        let description =
            Description::from_message(&headers, b"v=0\r\n").unwrap();
        assert_eq!(description.content_type(), "application/sdp");
        assert_eq!(description.body().as_ref(), b"v=0\r\n");
    }
}
