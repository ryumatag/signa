/*!
What this UA tells its peers it takes, in one place.

| Header | Value | Sent in |
| --- | --- | --- |
| Allow | [`ALLOW`] | each INVITE and re-INVITE, each 2xx to an INVITE, the 200 to OPTIONS, and each 405 the UA sends itself |
| Accept | [`ACCEPT`] | the 200 to OPTIONS, and each 415 the UA sends itself |
| Accept-Encoding | [`ACCEPT_ENCODING`] | the 200 to OPTIONS, and each 415 the UA sends itself |
| Supported | none | nothing, since the UA has no extension |
| Unsupported | each Require row of the request | each 420 the UA sends itself |

A method in [`KNOWN`] gets a 405 with the Allow above, and any other method
the UA does not take a 501 (RFC 3261 section 21.5.2). A rejection the
application chooses carries none of these, since
`IncomingInvite::try_reject` takes a status alone.

These values describe what the code that reads requests does. They do not
decide it. Which methods the driver takes, which bodies carry an offer and
which option tags pass the Require check are each written where the request
is read, so a value added here alone advertises something the UA does not
do. The loopback tests in `tests/uas.rs` send a peer's request for each value
the 200 to OPTIONS advertises, and fail when the UA does not take it.

The 200 to OPTIONS leaves out Accept-Language, since the UA reads no
language, and Supported, since the UA has no option tag to list and a peer
that requires one learns so from the 420 (RFC 3261 section 11.2 lists both as
SHOULD).
*/

use signa_core::Method;

/// The methods this UA takes: INVITE with the ACK and CANCEL that go with
/// it, BYE, and OPTIONS (RFC 3261 section 20.5).
pub(crate) const ALLOW: &str = "INVITE, ACK, CANCEL, BYE, OPTIONS";

/// The one body type the UA takes as an offer without a Content-Disposition
/// (RFC 3261 sections 20.1 and 20.11). A body of another type is still an
/// offer when its disposition says `session`, but a peer cannot tell that
/// from Accept, so the UA lists the type that needs nothing more. Accept is
/// not the list of what the UA refuses. A body of another type without that
/// disposition is no offer, and goes to the application as it is, except a
/// multipart one, which may hold an offer and gets a 415.
// Only the runtime answers requests, and the unit tests do not read these.
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) const ACCEPT: &str = "application/sdp";

/// The UA cannot undo a content coding, so it takes a session description
/// only without one (RFC 3261 section 20.2).
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) const ACCEPT_ENCODING: &str = "identity";

/// The methods of RFC 3261 and its extensions that the UA knows but does not
/// take. Each gets a 405 (RFC 3261 section 21.4.6).
pub(crate) const KNOWN: [Method; 9] = [
    Method::REGISTER,
    Method::PRACK,
    Method::SUBSCRIBE,
    Method::NOTIFY,
    Method::PUBLISH,
    Method::INFO,
    Method::REFER,
    Method::MESSAGE,
    Method::UPDATE,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// A method is either taken or answered with a 405, never both. INVITE
    /// brings its ACK and CANCEL along, since the transactions they end or
    /// stop are the INVITE's.
    #[test]
    fn a_method_is_taken_or_not_allowed() {
        let allowed: Vec<Method> =
            ALLOW.split(", ").map(|name| name.parse().unwrap()).collect();

        assert!(KNOWN.iter().all(|method| !allowed.contains(method)));
        for method in [Method::INVITE, Method::ACK, Method::CANCEL] {
            assert!(allowed.contains(&method), "{method}");
        }
    }
}
