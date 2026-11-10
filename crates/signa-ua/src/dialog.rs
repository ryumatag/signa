/*!
Dialog state: identity, phase, routing values and CSeq numbers.

A dialog is the SIP state that two user agents share. It knows nothing of the
usage that created it. INVITE, BYE and offer/answer live in `invite` and
`negotiation`, which refer to a dialog by its key. This module does not refer
back to them, so that SUBSCRIBE or REFER usages can share it later without
reworking it ([RFC 5057 section 3]).

A dialog is built from the message that forms it, as RFC 3261 sections 12.1.1
and 12.1.2 lay out, and builds the head of each request sent in it, as section
12.2.1.1 does. What it reads, it keeps as written: URIs with all their
parameters, and the Call-ID byte for byte. What it writes is normalized. From
and To get the dialog's URI in angle brackets and the tag, without the display
name or other parameters of the message that formed it. Section 12.2.1.1 asks
for the URIs and tags only.

RFC 3261 sections 12.1.1 and 12.1.2 require a UA to accept a peer that sends no
tag, as RFC 2543 allowed, so the remote tag may be null. The local tag is
always this user agent's own.

[RFC 5057 section 3]: https://www.rfc-editor.org/rfc/rfc5057.html#section-3
*/

use std::fmt;

use signa_core::{
    HeaderMap, Method, Request, Response,
    message::header::{CALL_ID, CSEQ, FROM, MAX_FORWARDS, ROUTE, TO, Tag},
};

use crate::{
    protocol::{self, Field, Malformed},
    routing::{
        InvalidRouteSet, Order, RemoteTarget, RequestTarget, RouteSet,
        request_target,
    },
    slot::Key,
};

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
    remote_tag: Option<Tag>,
}

impl DialogId {
    pub(crate) fn new(
        call_id: Box<str>,
        local_tag: Tag,
        remote_tag: Option<Tag>,
    ) -> DialogId {
        DialogId { call_id, local_tag, remote_tag }
    }

    pub(crate) fn call_id(&self) -> &str {
        &self.call_id
    }

    pub(crate) fn local_tag(&self) -> &Tag {
        &self.local_tag
    }

    /// Returns the peer's tag, or `None` for a peer that sent none.
    pub(crate) fn remote_tag(&self) -> Option<&Tag> {
        self.remote_tag.as_ref()
    }
}

impl fmt::Debug for DialogId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let remote = self.remote_tag.as_ref().map_or("", Tag::as_str);
        write!(f, "{};{};{}", self.call_id, self.local_tag, remote)
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

/// Why a message cannot form or update a dialog, or a dialog cannot change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DialogError {
    /// A header the dialog needs is missing or malformed.
    Malformed(Field),
    /// The route set is longer than the limit.
    RouteSetTooLong,
    /// The dialog has ended.
    Terminated,
}

impl From<Malformed> for DialogError {
    fn from(Malformed(field): Malformed) -> DialogError {
        DialogError::Malformed(field)
    }
}

impl From<InvalidRouteSet> for DialogError {
    fn from(error: InvalidRouteSet) -> DialogError {
        match error {
            InvalidRouteSet::Malformed => {
                DialogError::Malformed(Field::RecordRoute)
            }
            InvalidRouteSet::TooLong => DialogError::RouteSetTooLong,
        }
    }
}

/// What a UAC's request says about the dialogs it may form.
#[derive(Clone, Debug)]
pub(crate) struct Origin {
    call_id: Box<str>,
    local_tag: Tag,
    local_uri: Box<str>,
    cseq: u32,
}

impl Origin {
    /// Reads the request a UAC sends to form dialogs.
    ///
    /// The From must have a tag. RFC 3261 section 8.1.1.3 requires a UAC to
    /// add one, and this user agent always does.
    pub(crate) fn from_request<B>(
        request: &Request<B>,
    ) -> Result<Origin, DialogError> {
        let headers = request.headers();
        let from = protocol::from(headers)?;
        let local_tag = tag(from.tag, Field::From)?
            .ok_or(DialogError::Malformed(Field::From))?;

        Ok(Origin {
            call_id: protocol::call_id(headers)?.into(),
            local_tag,
            local_uri: from.uri.into(),
            cseq: protocol::cseq(headers)?.0,
        })
    }

    pub(crate) fn cseq(&self) -> u32 {
        self.cseq
    }

    /// Says whether a response carries the identity of the INVITE this was
    /// read from: its Call-ID, From tag and CSeq. The core matched the
    /// response to the transaction by its Via alone (RFC 3261 section
    /// 17.1.3), so one that changed any of these is not a response this
    /// request's dialogs can be formed from.
    pub(crate) fn answered_by<B>(&self, response: &Response<B>) -> bool {
        let headers = response.headers();
        let (Ok(call_id), Ok(from), Ok((cseq, method))) = (
            protocol::call_id(headers),
            protocol::from(headers),
            protocol::cseq(headers),
        ) else {
            return false;
        };

        call_id == &*self.call_id
            && from.tag == Some(self.local_tag.as_str())
            && cseq == self.cseq
            && method == "INVITE"
    }

    /// Returns the identity of the dialog a response with `remote_tag` forms.
    pub(crate) fn dialog_id(&self, remote_tag: Option<Tag>) -> DialogId {
        DialogId::new(self.call_id.clone(), self.local_tag.clone(), remote_tag)
    }
}

/// Parses a tag that `protocol` has already checked to be a token.
fn tag(tag: Option<&str>, field: Field) -> Result<Option<Tag>, DialogError> {
    tag.map(str::parse).transpose().map_err(|_| DialogError::Malformed(field))
}

/// Reads the dialog a request names, from this user agent's side, which
/// takes the To tag as local and the From tag as remote. A request without a
/// To tag names no dialog (RFC 3261 section 12.2.2).
pub(crate) fn request_dialog<B>(
    request: &Request<B>,
) -> Result<Option<DialogId>, DialogError> {
    let headers = request.headers();
    let Some(local_tag) = tag(protocol::to(headers)?.tag, Field::To)? else {
        return Ok(None);
    };
    let remote_tag = tag(protocol::from(headers)?.tag, Field::From)?;

    Ok(Some(DialogId::new(
        protocol::call_id(headers)?.into(),
        local_tag,
        remote_tag,
    )))
}

/// Reads the remote tag of a response, the tag of its To.
pub(crate) fn response_tag<B>(
    response: &Response<B>,
) -> Result<Option<Tag>, DialogError> {
    tag(protocol::to(response.headers())?.tag, Field::To)
}

/// Why a request is out of order in a dialog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutOfOrder {
    /// Its CSeq is below the last one. RFC 3261 section 12.2.2 rejects it
    /// with a 500.
    Lower,
    /// Its CSeq equals the last one.
    Repeated,
}

/// The largest CSeq number this user agent sends.
///
/// RFC 3261 section 8.1.1.5 keeps a CSeq below 2^31, and signa-core refuses
/// an INVITE at or above it, re-INVITEs included. I hold every request in a
/// dialog to the same bound, so that a request is never numbered past what
/// a later re-INVITE could use. A dialog that reaches it refuses new
/// requests instead of wrapping around.
const MAX_CSEQ: u32 = (1 << 31) - 1;

/// How a request in a dialog is numbered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Sequence {
    /// The next local number. `seed` is random and picks the first number
    /// when the dialog has none yet.
    Next { seed: u64 },
    /// The number of the request this one acknowledges or cancels.
    Of(u32),
}

/// Why a request could not be built in a dialog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestError {
    Terminated,
    /// ACK takes the number of its INVITE, and every other request takes
    /// the next number. The sequence asked for the other one.
    WrongSequence,
    /// A CANCEL copies the request it cancels, To tag and all (RFC 3261
    /// section 9.1), so it is not built from a dialog. signa-core's
    /// `ClientControl::cancel` builds it from the INVITE.
    Cancel,
    CSeqExhausted,
    /// A stored value no longer forms a valid header, which would be a bug.
    Invalid,
}

/// The head of a request in a dialog, and where it goes.
#[derive(Debug)]
pub(crate) struct Outgoing {
    /// The request with its Request-URI, To, From, Call-ID, CSeq,
    /// Max-Forwards and Route. The rest of RFC 3261 section 8.1.1, such as
    /// Via and Contact, is the caller's.
    pub(crate) request: Request<()>,
    pub(crate) target: RequestTarget,
}

/// The shared state of one dialog.
#[derive(Debug)]
pub(crate) struct Dialog {
    id: DialogId,
    phase: DialogPhase,
    local_uri: Box<str>,
    remote_uri: Box<str>,
    target: RemoteTarget,
    routes: RouteSet,
    /// `None` until this user agent sends a request that takes a number.
    local_cseq: Option<u32>,
    /// `None` until the peer sends a request in the dialog.
    remote_cseq: Option<u32>,
    /// Set for a dialog formed over TLS with a SIPS Request-URI (RFC 3261
    /// section 12.1). There is no TLS yet, so it stays `false`, and a SIPS
    /// URI alone still makes each request ask for a secure hop.
    secure: bool,
}

impl Dialog {
    /// Forms the dialog a UAS answers `request` in, with `local_tag` as the To
    /// tag of its responses (RFC 3261 section 12.1.1). The dialog starts
    /// early.
    pub(crate) fn uas<B>(
        request: &Request<B>,
        local_tag: Tag,
        route_limit: usize,
    ) -> Result<Dialog, DialogError> {
        let headers = request.headers();
        let from = protocol::from(headers)?;
        let to = protocol::to(headers)?;
        let contact = protocol::contact(headers)?
            .ok_or(DialogError::Malformed(Field::Contact))?;

        Ok(Dialog {
            id: DialogId::new(
                protocol::call_id(headers)?.into(),
                local_tag,
                tag(from.tag, Field::From)?,
            ),
            phase: DialogPhase::Early,
            local_uri: to.uri.into(),
            remote_uri: from.uri.into(),
            target: RemoteTarget::new(contact)
                .map_err(|_| DialogError::Malformed(Field::Contact))?,
            routes: RouteSet::from_record_route(
                headers,
                Order::AsReceived,
                route_limit,
            )?,
            local_cseq: None,
            remote_cseq: Some(protocol::cseq(headers)?.0),
            secure: false,
        })
    }

    /// Forms the dialog of a response with a To tag to the request `origin`
    /// was read from (RFC 3261 section 12.1.2). A 2xx forms it confirmed and
    /// a provisional response early.
    pub(crate) fn uac<B>(
        origin: &Origin,
        response: &Response<B>,
        route_limit: usize,
    ) -> Result<Dialog, DialogError> {
        let headers = response.headers();
        let to = protocol::to(headers)?;
        let contact = protocol::contact(headers)?
            .ok_or(DialogError::Malformed(Field::Contact))?;
        let phase = if response.status().is_success() {
            DialogPhase::Confirmed
        } else {
            DialogPhase::Early
        };

        Ok(Dialog {
            id: origin.dialog_id(tag(to.tag, Field::To)?),
            phase,
            local_uri: origin.local_uri.clone(),
            remote_uri: to.uri.into(),
            target: RemoteTarget::new(contact)
                .map_err(|_| DialogError::Malformed(Field::Contact))?,
            routes: RouteSet::from_record_route(
                headers,
                Order::Reversed,
                route_limit,
            )?,
            local_cseq: Some(origin.cseq),
            remote_cseq: None,
            secure: false,
        })
    }

    pub(crate) fn id(&self) -> &DialogId {
        &self.id
    }

    pub(crate) fn phase(&self) -> DialogPhase {
        self.phase
    }

    pub(crate) fn routes(&self) -> &RouteSet {
        &self.routes
    }

    pub(crate) fn target(&self) -> &RemoteTarget {
        &self.target
    }

    pub(crate) fn local_cseq(&self) -> Option<u32> {
        self.local_cseq
    }

    pub(crate) fn remote_cseq(&self) -> Option<u32> {
        self.remote_cseq
    }

    /// Moves an early dialog to confirmed, as a UAS does when the core takes
    /// its 2xx. Confirming a confirmed dialog does nothing.
    pub(crate) fn confirm(&mut self) -> Result<(), DialogError> {
        if self.phase == DialogPhase::Terminated {
            return Err(DialogError::Terminated);
        }

        self.phase = DialogPhase::Confirmed;
        Ok(())
    }

    /// Confirms an early dialog with the 2xx a UAC received for it.
    ///
    /// RFC 3261 section 13.2.2.4 recomputes the route set from the 2xx and
    /// nothing else. The CSeq numbers stay, since requests may have been sent
    /// in the early dialog. The 2xx answers the INVITE, a target refresh
    /// request, so its Contact replaces the remote target ([RFC 6141 sections
    /// 4.7 and 4.9]). On an error nothing changes.
    ///
    /// [RFC 6141 sections 4.7 and 4.9]: https://www.rfc-editor.org/rfc/rfc6141.html#section-4.7
    pub(crate) fn confirm_with<B>(
        &mut self,
        response: &Response<B>,
        route_limit: usize,
    ) -> Result<(), DialogError> {
        if self.phase == DialogPhase::Terminated {
            return Err(DialogError::Terminated);
        }
        let headers = response.headers();
        let routes = RouteSet::from_record_route(
            headers,
            Order::Reversed,
            route_limit,
        )?;
        let mut target = self.target.clone();
        if let Some(contact) = protocol::contact(headers)? {
            target
                .refresh(contact)
                .map_err(|_| DialogError::Malformed(Field::Contact))?;
        }

        self.routes = routes;
        self.target = target;
        self.phase = DialogPhase::Confirmed;
        Ok(())
    }

    /// Ends the dialog from any phase. Ending it twice does nothing.
    pub(crate) fn terminate(&mut self) {
        self.phase = DialogPhase::Terminated;
    }

    /// Replaces the remote target with the Contact of a target refresh,
    /// request or 2xx, if it has one (RFC 3261 sections 12.2.1.2 and 12.2.2).
    /// The route set stays, as RFC 3261 section 12.2 requires.
    pub(crate) fn refresh_target(
        &mut self,
        headers: &HeaderMap,
    ) -> Result<(), DialogError> {
        match protocol::contact(headers)? {
            Some(contact) => self
                .target
                .refresh(contact)
                .map_err(|_| DialogError::Malformed(Field::Contact)),
            None => Ok(()),
        }
    }

    /// Checks the CSeq of a request the peer sent in the dialog, and records
    /// it if the request is in order.
    ///
    /// RFC 3261 section 12.2.2 accepts any number above the last one, since a
    /// request challenged by a proxy leaves a gap. It rejects a lower one. A
    /// retransmission never gets here, because its server transaction in
    /// signa-core absorbs it. A new request with the last number is then a
    /// merged or replayed one, and I reject it too. The RFC does not say what
    /// to do with it. ACK and CANCEL carry the number of their INVITE and do
    /// not come here.
    pub(crate) fn remote_request(
        &mut self,
        cseq: u32,
    ) -> Result<(), OutOfOrder> {
        match self.remote_cseq {
            Some(last) if cseq < last => Err(OutOfOrder::Lower),
            Some(last) if cseq == last => Err(OutOfOrder::Repeated),
            _ => {
                self.remote_cseq = Some(cseq);
                Ok(())
            }
        }
    }

    /// Builds the head of a request in the dialog (RFC 3261 section
    /// 12.2.1.1).
    ///
    /// ACK takes [`Sequence::Of`] and leaves the local number alone. Every
    /// other method takes [`Sequence::Next`], which uses up the next number
    /// even if the request is never sent. A number that may have reached the
    /// peer is never given out again. CANCEL is refused, see
    /// [`RequestError::Cancel`].
    pub(crate) fn request(
        &mut self,
        method: Method,
        sequence: Sequence,
    ) -> Result<Outgoing, RequestError> {
        if self.phase == DialogPhase::Terminated {
            return Err(RequestError::Terminated);
        }
        if method == Method::CANCEL {
            return Err(RequestError::Cancel);
        }

        let cseq = match (sequence, method == Method::ACK) {
            (Sequence::Of(number), true) => number,
            (Sequence::Next { seed }, false) => self.next_cseq(seed)?,
            _ => return Err(RequestError::WrongSequence),
        };

        let target = request_target(&self.routes, &self.target, self.secure);
        let to = address(&self.remote_uri, self.id.remote_tag.as_ref());
        let from = address(&self.local_uri, Some(&self.id.local_tag));
        let cseq = format!("{cseq} {}", method.as_str());

        let mut builder = Request::builder()
            .method(method)
            .uri(target.request_uri.as_str())
            .header(TO, to.as_str())
            .header(FROM, from.as_str())
            .header(CALL_ID, self.id.call_id())
            .header(CSEQ, cseq.as_str())
            // RFC 3261 section 8.1.1.6.
            .header(MAX_FORWARDS, "70");
        for route in &target.route {
            builder = builder.header(ROUTE, format!("<{route}>").as_str());
        }

        let request = builder.body(()).map_err(|_| RequestError::Invalid)?;
        Ok(Outgoing { request, target })
    }

    fn next_cseq(&mut self, seed: u64) -> Result<u32, RequestError> {
        let next = match self.local_cseq {
            // RFC 3261 section 12.2.1.1 picks a first number by the rules of
            // section 8.1.1.5, which only bound it. I take it from the low
            // 16 bits of a random value, so that a restarted UA rarely
            // repeats an earlier number, and nearly all of the range below
            // 2^31 is left to count up in.
            None => (seed % (1 << 16)) as u32 + 1,
            Some(last) if last >= MAX_CSEQ => {
                return Err(RequestError::CSeqExhausted);
            }
            Some(last) => last + 1,
        };

        self.local_cseq = Some(next);
        Ok(next)
    }
}

/// Writes a From or To value for a request in a dialog.
fn address(uri: &str, tag: Option<&Tag>) -> String {
    match tag {
        Some(tag) => format!("<{uri}>;tag={tag}"),
        None => format!("<{uri}>"),
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use signa_core::message::header::CONTACT;

    use super::*;
    use crate::tests::{INVITE, reply, request};

    const ROUTES: usize = 8;

    fn ok(
        status: &str,
        tag: &str,
        record_route: &str,
        contact: &str,
    ) -> Response<Bytes> {
        reply(status, tag, contact, record_route)
    }

    fn uas() -> Dialog {
        crate::tests::dialog()
    }

    fn uac(response: Response<Bytes>) -> Dialog {
        let origin = Origin::from_request(&request(INVITE)).unwrap();
        Dialog::uac(&origin, &response, ROUTES).unwrap()
    }

    fn uris(dialog: &Dialog) -> Vec<&str> {
        dialog.routes().iter().map(|route| route.uri()).collect()
    }

    fn header(
        request: &Request<()>,
        name: signa_core::HeaderName,
    ) -> Vec<&str> {
        request.headers().get_all(name).map(|value| value.as_str()).collect()
    }

    #[test]
    fn uac_reverses_record_route_uas_preserves_order() {
        let record_route = "Record-Route: <sip:p1.example.com;lr>, <sip:p2.example.com;lr>\nRecord-Route: <sip:p3.example.com;lr>\n";
        let uac =
            uac(ok("200 OK", "a6c85cf", record_route, "sip:bob@192.0.2.4"));

        assert_eq!(
            uris(&uas()),
            [
                "sip:p1.example.com;lr",
                "sip:p2.example.com;lr",
                "sip:p3.example.com;lr"
            ],
        );
        assert_eq!(
            uris(&uac),
            [
                "sip:p3.example.com;lr",
                "sip:p2.example.com;lr",
                "sip:p1.example.com;lr"
            ],
        );
    }

    #[test]
    fn each_side_names_the_tags_and_uris_from_itself() {
        let uas = uas();
        let uac = uac(ok("200 OK", "a6c85cf", "", "sip:bob@192.0.2.4"));

        assert_eq!(uas.id().local_tag().as_str(), "a6c85cf");
        assert_eq!(uas.id().remote_tag().unwrap().as_str(), "1928301774");
        assert_eq!(uac.id().local_tag().as_str(), "1928301774");
        assert_eq!(uac.id().remote_tag().unwrap().as_str(), "a6c85cf");
        assert_eq!(
            uas.id().call_id(),
            "a84b4c76e66710@pc33.atlanta.example.com"
        );

        assert_eq!(
            (uas.local_cseq(), uas.remote_cseq()),
            (None, Some(314159))
        );
        assert_eq!(
            (uac.local_cseq(), uac.remote_cseq()),
            (Some(314159), None)
        );
        assert_eq!(uas.phase(), DialogPhase::Early);
        assert_eq!(uac.phase(), DialogPhase::Confirmed);
        assert_eq!(uas.target().uri(), "sip:alice@192.0.2.1");
        assert_eq!(uac.target().uri(), "sip:bob@192.0.2.4");
    }

    #[test]
    fn a_peer_without_a_tag_has_a_null_remote_tag() {
        let text = INVITE.replace(";tag=1928301774", "");
        let dialog =
            Dialog::uas(&request(&text), "a6c85cf".parse().unwrap(), ROUTES)
                .unwrap();

        assert_eq!(dialog.id().remote_tag(), None);
    }

    #[test]
    fn a_dialog_needs_one_sip_contact() {
        for contact in [
            "",
            "Contact: <tel:+15551234>\n",
            "Contact: <sip:a@192.0.2.1>, <sip:b@192.0.2.1>\n",
        ] {
            let text =
                INVITE.replace("Contact: <sip:alice@192.0.2.1>\n", contact);
            assert_eq!(
                Dialog::uas(
                    &request(&text),
                    "a6c85cf".parse().unwrap(),
                    ROUTES
                )
                .unwrap_err(),
                DialogError::Malformed(Field::Contact),
                "{contact:?}",
            );
        }
    }

    #[test]
    fn a_long_route_set_is_refused() {
        let error =
            Dialog::uas(&request(INVITE), "a6c85cf".parse().unwrap(), 2)
                .unwrap_err();

        assert_eq!(error, DialogError::RouteSetTooLong);
    }

    /// An early dialog has sent a request of its own when the 2xx arrives.
    /// The 2xx brings a new route set and target, and the numbers stay.
    #[test]
    fn confirmed_transition_preserves_sequence_history() {
        let mut dialog = uac(ok(
            "180 Ringing",
            "a6c85cf",
            "Record-Route: <sip:p1.example.com;lr>\n",
            "sip:bob@192.0.2.4",
        ));
        let info = Method::try_from("INFO").unwrap();
        dialog.request(info.clone(), Sequence::Next { seed: 0 }).unwrap();
        dialog.remote_request(7).unwrap();

        dialog
            .confirm_with(
                &ok(
                    "200 OK",
                    "a6c85cf",
                    "Record-Route: <sip:p2.example.com;lr>, <sip:p1.example.com;lr>\n",
                    "sip:bob@192.0.2.5",
                ),
                ROUTES,
            )
            .unwrap();

        assert_eq!(dialog.phase(), DialogPhase::Confirmed);
        assert_eq!(
            uris(&dialog),
            ["sip:p1.example.com;lr", "sip:p2.example.com;lr"]
        );
        assert_eq!(dialog.target().uri(), "sip:bob@192.0.2.5");
        assert_eq!(dialog.local_cseq(), Some(314160));
        assert_eq!(dialog.remote_cseq(), Some(7));

        let next = dialog.request(info, Sequence::Next { seed: 0 }).unwrap();
        assert_eq!(header(&next.request, CSEQ), ["314161 INFO"]);
    }

    #[test]
    fn a_failed_confirmation_changes_nothing() {
        let mut dialog =
            uac(ok("180 Ringing", "a6c85cf", "", "sip:bob@192.0.2.4"));

        let bad = ok(
            "200 OK",
            "a6c85cf",
            "Record-Route: sip:p1.example.com;lr\n",
            "sip:bob@192.0.2.5",
        );
        assert!(dialog.confirm_with(&bad, ROUTES).is_err());

        assert_eq!(dialog.phase(), DialogPhase::Early);
        assert_eq!(dialog.target().uri(), "sip:bob@192.0.2.4");
    }

    #[test]
    fn cseq_gap_is_accepted_lower_value_is_rejected() {
        let mut dialog = uas();

        assert_eq!(dialog.remote_request(314161), Ok(()));
        assert_eq!(dialog.remote_request(314200), Ok(()));
        assert_eq!(dialog.remote_request(314199), Err(OutOfOrder::Lower));
        assert_eq!(dialog.remote_request(314200), Err(OutOfOrder::Repeated));
        assert_eq!(dialog.remote_cseq(), Some(314200));
    }

    #[test]
    fn ack_and_cancel_do_not_allocate_new_dialog_cseq() {
        let mut dialog = uac(ok("200 OK", "a6c85cf", "", "sip:bob@192.0.2.4"));

        let ack = dialog.request(Method::ACK, Sequence::Of(314159)).unwrap();
        let cancel = dialog.request(Method::CANCEL, Sequence::Of(314159));

        assert_eq!(header(&ack.request, CSEQ), ["314159 ACK"]);
        // A CANCEL copies its INVITE, which signa-core does, so the dialog
        // builds none, and none takes a number.
        assert_eq!(cancel.unwrap_err(), RequestError::Cancel);
        assert_eq!(dialog.local_cseq(), Some(314159));

        for (method, sequence) in [
            (Method::ACK, Sequence::Next { seed: 0 }),
            (Method::BYE, Sequence::Of(314159)),
        ] {
            assert_eq!(
                dialog.request(method, sequence).unwrap_err(),
                RequestError::WrongSequence,
            );
        }
        assert_eq!(dialog.local_cseq(), Some(314159));

        let bye =
            dialog.request(Method::BYE, Sequence::Next { seed: 0 }).unwrap();
        assert_eq!(header(&bye.request, CSEQ), ["314160 BYE"]);
    }

    #[test]
    fn a_uas_picks_its_first_number_below_2_16() {
        let mut dialog = uas();

        let bye = dialog
            .request(Method::BYE, Sequence::Next { seed: u64::MAX })
            .unwrap();

        assert_eq!(header(&bye.request, CSEQ), ["65536 BYE"]);
    }

    #[test]
    fn cseq_stops_below_2_31() {
        let mut dialog = uas();
        dialog.local_cseq = Some(MAX_CSEQ - 1);

        dialog.request(Method::BYE, Sequence::Next { seed: 0 }).unwrap();
        assert_eq!(
            dialog
                .request(Method::BYE, Sequence::Next { seed: 0 })
                .unwrap_err(),
            RequestError::CSeqExhausted,
        );
        assert_eq!(dialog.local_cseq(), Some(MAX_CSEQ));
    }

    /// The request follows RFC 3261 section 12.2.1.1 from the UAS side, with
    /// the From and To of the dialog-forming INVITE swapped.
    #[test]
    fn requests_carry_the_dialog_state() {
        let mut dialog = uas();

        let bye =
            dialog.request(Method::BYE, Sequence::Next { seed: 41 }).unwrap();

        assert_eq!(bye.request.method(), &Method::BYE);
        assert_eq!(bye.request.uri().as_str(), "sip:alice@192.0.2.1");
        assert_eq!(
            header(&bye.request, TO),
            ["<sip:alice@atlanta.example.com>;tag=1928301774"]
        );
        assert_eq!(
            header(&bye.request, FROM),
            ["<sip:bob@biloxi.example.com>;tag=a6c85cf"]
        );
        assert_eq!(
            header(&bye.request, CALL_ID),
            ["a84b4c76e66710@pc33.atlanta.example.com"]
        );
        assert_eq!(header(&bye.request, CSEQ), ["42 BYE"]);
        assert_eq!(header(&bye.request, MAX_FORWARDS), ["70"]);
        assert_eq!(
            header(&bye.request, ROUTE),
            [
                "<sip:p1.example.com;lr>",
                "<sip:p2.example.com;lr>",
                "<sip:p3.example.com;lr>"
            ],
        );
        assert_eq!(&*bye.target.next_hop, "sip:p1.example.com;lr");
    }

    #[test]
    fn a_contact_refresh_keeps_the_route_set() {
        let mut dialog = uas();
        let mut headers = HeaderMap::new();
        headers.append(CONTACT, "<sip:alice@192.0.2.9>".try_into().unwrap());

        dialog.refresh_target(&headers).unwrap();
        dialog.refresh_target(&HeaderMap::new()).unwrap();

        assert_eq!(dialog.target().uri(), "sip:alice@192.0.2.9");
        assert_eq!(uris(&dialog).len(), 3);
    }

    #[test]
    fn a_terminated_dialog_stays_terminated() {
        let mut dialog = uas();
        dialog.terminate();

        assert_eq!(dialog.confirm(), Err(DialogError::Terminated));
        assert_eq!(
            dialog
                .request(Method::BYE, Sequence::Next { seed: 0 })
                .unwrap_err(),
            RequestError::Terminated,
        );
        assert_eq!(dialog.phase(), DialogPhase::Terminated);
    }
}
