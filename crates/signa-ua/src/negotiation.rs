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
}
