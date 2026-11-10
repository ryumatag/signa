/*!
Dialog identity and phase.

A dialog is the SIP state that two user agents share: its identity, the routing
material and the CSeq numbers in each direction. It knows nothing of the usage
that created it. INVITE, BYE and offer/answer live in `invite` and
`negotiation`, which refer to a dialog by its key. This module does not refer
back to them, so that SUBSCRIBE or REFER usages can share it later without
reworking it ([RFC 5057 section 3]).

TODO: Add the route set, the local and remote targets and URIs, and the CSeq
numbers in each direction, with their parsing and validated updates. Only the
identity and the phase are here so far.

[RFC 5057 section 3]: https://www.rfc-editor.org/rfc/rfc5057.html#section-3
*/

use std::fmt;

use signa_core::message::header::Tag;

use crate::slot::Key;

/// The local address of a [`Dialog`] in the model's table.
///
/// It is not the dialog's identity on the wire, which is [`DialogId`]. A key
/// goes stale when the dialog record is reclaimed, while the `DialogId` stays
/// the same for as long as messages of the dialog can arrive.
pub(crate) type DialogKey = Key<Dialog>;

/// The identity of a dialog on the wire: the Call-ID and the two tags
/// ([RFC 3261 section 12]).
///
/// The tags are named from this user agent's side. The local tag is the From
/// tag of the requests it sends and the To tag of the requests it receives.
/// Naming them by side rather than by From and To keeps a UAC and a UAS of
/// the same call from mixing them up.
///
/// Before a response with a To tag arrives, an outgoing INVITE has no
/// `DialogId`. The model tracks it as an attempt instead of making one up.
///
/// [RFC 3261 section 12]: https://www.rfc-editor.org/rfc/rfc3261.html#section-12
#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct DialogId {
    call_id: Box<str>,
    local_tag: Tag,
    remote_tag: Tag,
}

impl DialogId {
    pub(crate) fn new(
        call_id: Box<str>,
        local_tag: Tag,
        remote_tag: Tag,
    ) -> DialogId {
        DialogId { call_id, local_tag, remote_tag }
    }

    pub(crate) fn call_id(&self) -> &str {
        &self.call_id
    }

    pub(crate) fn local_tag(&self) -> &Tag {
        &self.local_tag
    }

    pub(crate) fn remote_tag(&self) -> &Tag {
        &self.remote_tag
    }
}

impl fmt::Debug for DialogId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{};{};{}", self.call_id, self.local_tag, self.remote_tag)
    }
}

/// Where a dialog is in its life.
///
/// A dialog is confirmed by a 2xx, not by its ACK ([RFC 3261 section 12.1]).
/// Confirmed says nothing about the ACK, the offer/answer exchange or media,
/// which the usage and the replay context track on axes of their own.
///
/// [RFC 3261 section 12.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-12.1
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DialogPhase {
    /// Created by a provisional response with a To tag.
    Early,
    /// Created or confirmed by a 2xx.
    Confirmed,
    /// Ended. The phase is final.
    ///
    /// The model reclaims a terminated dialog's record. Messages that still
    /// arrive for it are matched by the replay contexts, which outlive it.
    Terminated,
}

/// A transition the phase does not allow, which no wire effect follows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvalidTransition {
    pub(crate) from: DialogPhase,
    pub(crate) to: DialogPhase,
}

/// The shared state of one dialog.
#[derive(Debug)]
pub(crate) struct Dialog {
    id: DialogId,
    phase: DialogPhase,
}

impl Dialog {
    pub(crate) fn early(id: DialogId) -> Dialog {
        Dialog { id, phase: DialogPhase::Early }
    }

    pub(crate) fn confirmed(id: DialogId) -> Dialog {
        Dialog { id, phase: DialogPhase::Confirmed }
    }

    pub(crate) fn id(&self) -> &DialogId {
        &self.id
    }

    pub(crate) fn phase(&self) -> DialogPhase {
        self.phase
    }

    /// Moves an early dialog to confirmed. Confirming a confirmed dialog does
    /// nothing, since a 2xx can be retransmitted.
    pub(crate) fn confirm(&mut self) -> Result<(), InvalidTransition> {
        match self.phase {
            DialogPhase::Early | DialogPhase::Confirmed => {
                self.phase = DialogPhase::Confirmed;
                Ok(())
            }
            DialogPhase::Terminated => Err(InvalidTransition {
                from: self.phase,
                to: DialogPhase::Confirmed,
            }),
        }
    }

    /// Ends the dialog from any phase. Ending it twice does nothing.
    pub(crate) fn terminate(&mut self) {
        self.phase = DialogPhase::Terminated;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> DialogId {
        DialogId::new(
            "a84b4c76e66710".into(),
            "1928301774".parse().unwrap(),
            "a6c85cf".parse().unwrap(),
        )
    }

    #[test]
    fn early_dialogs_confirm_and_terminate() {
        let mut dialog = Dialog::early(id());

        dialog.confirm().unwrap();
        assert_eq!(dialog.phase(), DialogPhase::Confirmed);
        dialog.confirm().unwrap();
        assert_eq!(dialog.phase(), DialogPhase::Confirmed);

        dialog.terminate();
        assert_eq!(dialog.phase(), DialogPhase::Terminated);
    }

    #[test]
    fn a_terminated_dialog_stays_terminated() {
        let mut dialog = Dialog::confirmed(id());
        dialog.terminate();

        assert_eq!(
            dialog.confirm(),
            Err(InvalidTransition {
                from: DialogPhase::Terminated,
                to: DialogPhase::Confirmed,
            }),
        );
        assert_eq!(dialog.phase(), DialogPhase::Terminated);
    }

    #[test]
    fn the_tags_keep_their_sides() {
        let swapped = DialogId::new(
            "a84b4c76e66710".into(),
            "a6c85cf".parse().unwrap(),
            "1928301774".parse().unwrap(),
        );

        assert_ne!(id(), swapped);
        assert_eq!(id().local_tag().as_str(), "1928301774");
        assert_eq!(id().remote_tag().as_str(), "a6c85cf");
    }
}
