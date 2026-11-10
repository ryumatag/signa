/*!
Messages sent once, outside any transaction.

[`Endpoint::send_request`] sends a request and [`Endpoint::forward_response`]
forwards a response. A stateful endpoint uses the first for the ACK a UAC core
sends for each 2xx ([RFC 3261 section 13.2.2.4]), which no transaction
carries, and for requests whose responses it does not observe.
A stateless proxy forwards requests with a branch it computed, and responses
by their remaining Via ([RFC 3261 section 16.11]).

[RFC 3261 section 13.2.2.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4
[RFC 3261 section 16.11]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.11
*/

use std::{error, fmt, future::Future, str::FromStr};

use bytes::Bytes;
use tokio::sync::oneshot;

use super::{
    Endpoint, Error, builder::Reception, client::Target, driver::Command,
    reply::Completion, routing::forward_destination,
};
use crate::{
    message::{
        Request, Response,
        header::{CSEQ, HeaderValue, VIA, cseq::CSeq, via::Via},
    },
    transport::{Flow, Transport},
};

/// Room the reservation of a request leaves for the Via the driver adds, apart
/// from its branch.
///
/// The Via is `SIP/2.0/UDP`, a `sent-by` of at most an IPv6 address with a
/// scope and a port, and `;rport;branch=`, with its name and line end. That
/// is under 100 bytes.
const VIA_ALLOWANCE: usize = 128;

/// The length of a fresh branch: the magic cookie, a 10-character prefix and
/// a 64-bit counter in hex.
const FRESH_BRANCH: usize = 33;

/// The magic cookie that starts every branch an RFC 3261 element makes
/// ([RFC 3261 section 8.1.1.7]).
///
/// [RFC 3261 section 8.1.1.7]: https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.7
const COOKIE: &str = "z9hG4bK";

/// The longest [`Branch`] accepted. RFC 3261 sets no limit, but a branch
/// several hundred bytes long is not one an element computed for matching.
const MAX_BRANCH: usize = 256;

/// How [`Endpoint::send_request`] makes the Via it prepends.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ViaMode {
    /// A Via with a branch the endpoint makes, unique among its requests.
    ///
    /// This is for a request that is a new transaction identity, such as a UAC
    /// core's ACK for a 2xx. That ACK has a branch of its own
    /// ([RFC 3261 section 8.1.1.7]) and goes straight to the transport, not to
    /// a client transaction ([RFC 3261 section 13.2.2.4]). The ACK for a
    /// non-2xx is another thing. It reuses the INVITE's branch, belongs to the
    /// INVITE's client transaction ([RFC 3261 section 17.1.1.3]), and signa
    /// sends it itself.
    ///
    /// Each call makes a new branch, so a proxy must not forward with it. A
    /// retransmission would reach the next hop as a new transaction.
    ///
    /// [RFC 3261 section 8.1.1.7]: https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.7
    /// [RFC 3261 section 13.2.2.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4
    /// [RFC 3261 section 17.1.1.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.3
    Fresh,
    /// A Via with the caller's branch, exactly as given.
    ///
    /// The endpoint checks the branch's syntax through [`Branch`] and nothing
    /// else. It neither makes it unique nor keeps it stable. A stateless proxy
    /// computes the same branch for every retransmission of a request, and
    /// for the CANCEL and non-2xx ACK that share the INVITE's branch, from
    /// inputs that do not change between them ([RFC 3261 section 16.11]). The
    /// method is not one of those inputs. A different request needs a
    /// different branch ([RFC 3261 section 8.1.1.7]).
    ///
    /// [RFC 3261 section 8.1.1.7]: https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.7
    /// [RFC 3261 section 16.11]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.11
    Branch(Branch),
}

/// A `branch` for a Via that [`Endpoint::send_request`] prepends.
///
/// It is a SIP `token` ([RFC 3261 section 25.1]) that starts with the magic
/// cookie `z9hG4bK`, in that letter case, and has something after it, since an
/// RFC 3261 element's branch identifies a transaction by it
/// ([RFC 3261 section 8.1.1.7]). It is at most 256 bytes long. Parsing checks
/// that syntax only. Whether the branch is unique, or stable across
/// retransmissions, is up to whoever computed it.
///
/// # Example
///
/// ```
/// use signa_core::endpoint::Branch;
///
/// let branch: Branch = "z9hG4bK-proxy-1f3a2c".parse()?;
/// assert_eq!(branch.as_str(), "z9hG4bK-proxy-1f3a2c");
///
/// assert!("1f3a2c".parse::<Branch>().is_err());
/// assert!("z9hG4bK".parse::<Branch>().is_err());
/// assert!("z9hG4bK a".parse::<Branch>().is_err());
/// # Ok::<(), signa_core::endpoint::InvalidBranch>(())
/// ```
///
/// [RFC 3261 section 25.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-25.1
/// [RFC 3261 section 8.1.1.7]: https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.7
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Branch(Box<str>);

impl Branch {
    /// Returns the branch as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Branch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for Branch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Branch {
    type Err = InvalidBranch;

    fn from_str(src: &str) -> Result<Branch, InvalidBranch> {
        let valid = src.len() > COOKIE.len()
            && src.len() <= MAX_BRANCH
            && src.starts_with(COOKIE)
            && matches!(siparse::scan::token(src), Some((_, "")));
        if valid { Ok(Branch(src.into())) } else { Err(InvalidBranch(())) }
    }
}

/// The error of parsing a [`Branch`].
#[derive(Debug)]
pub struct InvalidBranch(());

impl fmt::Display for InvalidBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "a branch is a token of at most 256 bytes that starts with \
             z9hG4bK and continues after it",
        )
    }
}

impl error::Error for InvalidBranch {}

/// What a request sent by [`Endpoint::send_request`] went out with.
#[derive(Clone, Debug)]
pub struct SentRequest {
    pub(super) via: HeaderValue,
    pub(super) flow: Flow,
}

impl SentRequest {
    /// The Via the endpoint prepended.
    pub fn via(&self) -> &HeaderValue {
        &self.via
    }

    /// The flow it went out on, including the selected local address.
    pub fn flow(&self) -> Flow {
        self.flow
    }
}

impl Endpoint {
    /// Sends `request` once to `target`, without a transaction, and waits for
    /// its local write result.
    ///
    /// The endpoint prepends one Via as `via` says, keeping the Via rows the
    /// request has and their order, and sends the request once. It creates no
    /// client transaction, so nothing retransmits the request, times it out,
    /// observes its responses or cancels it. Any method can go, extension
    /// methods included, as long as its CSeq names it.
    ///
    /// # Uses
    ///
    /// A stateful endpoint uses this for requests whose responses it does not
    /// observe. The usual one is the ACK a UAC core builds for a 2xx from its
    /// dialog, sends to the target it chose with [`ViaMode::Fresh`], and
    /// repeats for each retransmitted 2xx ([RFC 3261 section 13.2.2.4]). The
    /// 2xx itself arrives through the INVITE's [`Responses`]. A response to a
    /// request sent here matches no client transaction and is discarded. A
    /// request that needs its responses goes through [`Endpoint::start`]. Do
    /// not use this to send an INVITE again with a new branch, or to cancel an
    /// INVITE of [`Endpoint::start`] around [`ClientControl::cancel`].
    ///
    /// A stateless endpoint uses this to forward requests, with
    /// [`ViaMode::Branch`] and a branch computed from what does not change
    /// between retransmissions ([RFC 3261 section 16.11]). The responses arrive
    /// as [`IncomingEvent::StatelessResponse`] and go on through
    /// [`Endpoint::forward_response`]. Only UDP targets are supported, see
    /// [`Reception::Stateless`].
    ///
    /// # Routing
    ///
    /// Routing is the caller's, as for [`Endpoint::start`]. The only check
    /// refuses a `sips:` Request-URI in any letter case. Route and `target`
    /// are sent as given, nothing compares them with each other or resolves a
    /// URI ([RFC 3263 section 4.1]), and a request that needs TLS, for example
    /// for a `sips:` Route ([RFC 5630 section 5.1.1]), must not be sent through
    /// this endpoint. A `sip:` Request-URI does not make plaintext acceptable.
    /// A proxy's request processing ([RFC 3261 section 16.6]), such as
    /// Max-Forwards, Route and Record-Route, is the caller's as well.
    ///
    /// A UDP request above 1300 bytes, counting the Via added here, is refused
    /// as [RFC 3261 section 18.1.1] asks when the path MTU is unknown. The
    /// endpoint does not switch it to TCP. The caller picks a TCP target if it
    /// has one.
    ///
    /// The request can be sent while the endpoint shuts down, since a 2xx can
    /// arrive while admitted INVITEs drain.
    ///
    /// # Cancellation
    ///
    /// An unpolled future does nothing. Waiting for one of the 64 one-shot
    /// slots that reply routes share is cancellation-safe. Enqueue commits the
    /// request, and dropping the future after that does not withdraw it. The
    /// caller then does not learn the write result and must not blindly send
    /// again. Success means the local write finished, not that the peer got
    /// it. A TCP error may follow a partial write, so an error does not prove
    /// that nothing reached the peer.
    ///
    /// # Errors
    ///
    /// * [`Error::is_missing_header`] for a request without CSeq.
    /// * [`Error::is_invalid_cseq`] unless the request's CSeq is one value
    ///   with its own method.
    /// * [`Error::is_unsupported_routing`] for a `sips:` Request-URI, a
    ///   multicast target, a UDP target on an endpoint without a UDP socket,
    ///   or a TCP target on a stateless endpoint.
    /// * [`Error::is_too_large`] for a UDP request over 1300 bytes.
    /// * [`Error::is_busy`] when the one-shot byte budget,
    ///   [`Builder::max_reply_bytes`], the transport's output or the
    ///   connection limits are full.
    /// * [`Error::is_transport`] when a connection or the write fails.
    /// * [`Error::is_closed`] once the endpoint has stopped.
    ///
    /// # Example
    ///
    /// ```
    /// use bytes::Bytes;
    /// use signa_core::{
    ///     endpoint::{Endpoint, Error, Target, ViaMode},
    ///     Request,
    /// };
    ///
    /// // `ack` is built by the UAC core from the dialog of the 2xx.
    /// async fn acknowledge(
    ///     endpoint: &Endpoint,
    ///     ack: Request<Bytes>,
    ///     target: Target,
    /// ) -> Result<(), Error> {
    ///     let sent =
    ///         endpoint.send_request(ack, target, ViaMode::Fresh).await?;
    ///     println!("ACK sent with {}", sent.via().as_str());
    ///     Ok(())
    /// }
    /// ```
    ///
    /// [RFC 3261 section 13.2.2.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4
    /// [RFC 3261 section 16.6]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.6
    /// [RFC 3261 section 16.11]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.11
    /// [RFC 3261 section 18.1.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.1.1
    /// [RFC 3263 section 4.1]: https://www.rfc-editor.org/rfc/rfc3263.html#section-4.1
    /// [RFC 5630 section 5.1.1]: https://www.rfc-editor.org/rfc/rfc5630.html#section-5.1.1
    /// [`Builder::max_reply_bytes`]: super::Builder::max_reply_bytes
    /// [`Responses`]: super::Responses
    /// [`ClientControl::cancel`]: super::ClientControl::cancel
    /// [`IncomingEvent::StatelessResponse`]: super::IncomingEvent::StatelessResponse
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn send_request(
        &self,
        request: Request<Bytes>,
        target: Target,
        via: ViaMode,
    ) -> impl Future<Output = Result<SentRequest, Error>> + Send + '_ {
        async move {
            validate(&request)?;
            let unavailable = match target.transport() {
                Transport::Udp => self.udp.is_none(),
                Transport::Tcp => self.reception == Reception::Stateless,
            };
            if target.address().ip().is_multicast() || unavailable {
                return Err(Error::unsupported_routing());
            }
            if self.commands.is_closed() {
                return Err(Error::closed());
            }
            let branch = match &via {
                ViaMode::Fresh => FRESH_BRANCH,
                ViaMode::Branch(branch) => branch.as_str().len(),
            };
            let len = request
                .encoded_len()
                .and_then(|len| len.checked_add(VIA_ALLOWANCE + branch))
                .ok_or_else(|| Error::too_large(usize::MAX))?;

            let permit = self
                .oneshot_capacity
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| Error::closed())?;
            let reservation =
                self.oneshot_bytes.acquire(len).ok_or_else(Error::busy)?;

            let (done, result) = oneshot::channel();
            self.commands
                .send(Command::Request {
                    request,
                    target,
                    via,
                    completion: Completion::request(
                        done,
                        permit,
                        self.commands.clone(),
                        reservation,
                    ),
                })
                .map_err(|_| Error::closed())?;
            result.await.unwrap_or_else(|_| Err(Error::closed()))
        }
    }

    /// Forwards `response` once over UDP to where its top Via says, and waits
    /// for its local write result.
    ///
    /// This is the sending half of a stateless proxy's response processing
    /// ([RFC 3261 section 16.11]). Only a [`Reception::Stateless`] endpoint
    /// offers it. No transaction is involved, and the response goes out
    /// exactly as given, body and every header included.
    ///
    /// # What the caller does first
    ///
    /// The endpoint does not check whose response this is. Before calling it,
    /// the TU of a stateless proxy:
    ///
    /// 1. Reads the `sent-by` of the topmost Via value of the received
    ///    response, and discards the response unless that is an address this
    ///    proxy put in the requests it forwarded.
    /// 2. Removes that one Via value. It is the first value of the first Via
    ///    row, which may hold several values separated by commas, so removing
    ///    the whole row can remove other hops' values too.
    /// 3. Passes the response with the remaining Via values here.
    ///
    /// Skipping the first step turns the proxy into a reflector that sends
    /// whatever arrives to wherever its Via points.
    ///
    /// # Routing
    ///
    /// The destination comes from the remaining top Via
    /// ([RFC 3261 section 18.2.2], [RFC 3581 section 4]). It is the address of
    /// `received`, with the port of `rport` when both are present, or else the
    /// `sent-by` port, or 5060. Without `received` the `sent-by` must be an IP
    /// address, IPv4 or IPv6. The endpoint does not resolve host names, and
    /// never guesses a destination from the address a message came from.
    ///
    /// The 1300-byte limit of [RFC 3261 section 18.1.1] applies to requests,
    /// so a larger response still goes over UDP. The UDP write limits of
    /// [`Builder::udp_write_limits`] and the kernel decide whether it fits.
    ///
    /// # Cancellation
    ///
    /// As for [`Endpoint::send_request`]. Enqueue commits the response, and
    /// success means the local write finished.
    ///
    /// # Errors
    ///
    /// * [`Error::is_unsupported_reception`] on a stateful endpoint.
    /// * [`Error::is_invalid_header`] when the response has no Via, its top
    ///   value does not parse, its `received` is not an IP address, or the
    ///   port it names is zero.
    /// * [`Error::is_unsupported_routing`] when the top Via names a transport
    ///   other than UDP, has `maddr`, names a host other than an IP address
    ///   without `received`, or leads to a multicast or unspecified address.
    /// * [`Error::is_busy`] when [`Builder::max_reply_bytes`] or the UDP
    ///   output is full. Waiting for one of the 64 one-shot slots is not an
    ///   error.
    /// * [`Error::is_transport`] when the source address toward the
    ///   destination cannot be found or the write fails.
    /// * [`Error::is_closed`] once the endpoint has stopped.
    ///
    /// # Example
    ///
    /// ```
    /// use bytes::Bytes;
    /// use signa_core::{endpoint::{Endpoint, Error}, Response};
    ///
    /// // `response` arrived as a stateless response event. The TU checked
    /// // that its top Via was this proxy's and removed that value.
    /// async fn relay(
    ///     endpoint: &Endpoint,
    ///     response: Response<Bytes>,
    /// ) -> Result<(), Error> {
    ///     endpoint.forward_response(response).await
    /// }
    /// ```
    ///
    /// [RFC 3261 section 16.11]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.11
    /// [RFC 3261 section 18.1.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.1.1
    /// [RFC 3261 section 18.2.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2
    /// [RFC 3581 section 4]: https://www.rfc-editor.org/rfc/rfc3581.html#section-4
    /// [`Builder::max_reply_bytes`]: super::Builder::max_reply_bytes
    /// [`Builder::udp_write_limits`]: super::Builder::udp_write_limits
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn forward_response(
        &self,
        response: Response<Bytes>,
    ) -> impl Future<Output = Result<(), Error>> + Send + '_ {
        async move {
            if self.reception != Reception::Stateless {
                return Err(Error::unsupported_reception());
            }
            let remote = response
                .headers()
                .get(VIA)
                .and_then(Via::top)
                .ok_or_else(|| Error::invalid_header(VIA))
                .and_then(|via| forward_destination(&via))?;
            if self.commands.is_closed() {
                return Err(Error::closed());
            }
            let len = response
                .encoded_len()
                .ok_or_else(|| Error::too_large(usize::MAX))?;

            let permit = self
                .oneshot_capacity
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| Error::closed())?;
            let reservation =
                self.oneshot_bytes.acquire(len).ok_or_else(Error::busy)?;

            let bytes = response.to_bytes_reserved(len);
            drop(response);
            let (done, result) = oneshot::channel();
            self.commands
                .send(Command::Forward {
                    bytes,
                    remote,
                    completion: Completion::forward(
                        done,
                        permit,
                        self.commands.clone(),
                        reservation,
                    ),
                })
                .map_err(|_| Error::closed())?;
            result.await.unwrap_or_else(|_| Err(Error::closed()))
        }
    }
}

/// Checks the request before it takes any capacity.
fn validate(request: &Request<Bytes>) -> Result<(), Error> {
    // The same Request-URI guard as `start`, see its routing section.
    if request
        .uri()
        .as_str()
        .get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("sips:"))
    {
        return Err(Error::unsupported_routing());
    }

    // RFC 3261 section 8.1.1.5 gives the CSeq the request's method. A CANCEL
    // and an ACK carry their own method there, not the INVITE's.
    let mut values = request.headers().get_all(CSEQ);
    let value = values.next().ok_or_else(|| Error::missing(CSEQ))?;
    if values.next().is_some()
        || !CSeq::parse(value)
            .is_some_and(|cseq| cseq.method == *request.method())
    {
        return Err(Error::invalid_cseq());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::header::ROUTE;

    fn request(method: &str, uri: &str, cseq: &str) -> Request<Bytes> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("CSeq", cseq)
            .body(Bytes::new())
            .unwrap()
    }

    // RFC 3261 section 8.1.1.5. Any method goes, extension methods included,
    // when its CSeq names it.
    #[test]
    fn any_method_with_its_own_cseq_is_sent() {
        for method in ["ACK", "INVITE", "OPTIONS", "CANCEL", "BYE", "PUBLISH"]
        {
            let cseq = format!("1 {method}");
            assert!(
                validate(&request(method, "sip:bob@example.com", &cseq))
                    .is_ok(),
                "{method}"
            );
        }

        for (method, cseq) in [
            ("ACK", "1 INVITE"),
            ("CANCEL", "1 INVITE"),
            ("INVITE", "1 ACK"),
            ("ACK", "x ACK"),
            ("ACK", "1 ACK, 2 ACK"),
            // Methods are case-sensitive (RFC 3261 section 7.1).
            ("ack", "1 ACK"),
        ] {
            let error =
                validate(&request(method, "sip:bob@example.com", cseq))
                    .unwrap_err();
            assert!(error.is_invalid_cseq(), "{method} with {cseq}");
            assert!(!error.is_missing_header(), "{method} with {cseq}");
        }

        for method in ["ACK", "CANCEL", "OPTIONS"] {
            let cseq = format!("1 {method}");
            let mut request = request(method, "sip:bob@example.com", &cseq);
            request.headers_mut().remove(CSEQ);
            let error = validate(&request).unwrap_err();
            assert!(error.is_missing_header(), "{method}: {error}");
            assert!(!error.is_invalid_cseq(), "{method}: {error}");
        }
    }

    // RFC 3261 section 8.1.2 needs TLS for a SIPS Request-URI. Route is the
    // caller's, so a `sips:` Route goes out as given.
    #[test]
    fn a_sips_request_uri_is_refused_in_any_case() {
        for uri in ["sips:bob@example.com", "SIPS:bob@example.com"] {
            let error = validate(&request("ACK", uri, "1 ACK")).unwrap_err();
            assert!(error.is_unsupported_routing(), "{uri}");
        }

        let mut routed =
            request("OPTIONS", "sip:bob@example.com", "1 OPTIONS");
        routed.headers_mut().append(
            ROUTE,
            HeaderValue::from_static("<sips:proxy.example.com;lr>"),
        );
        assert!(validate(&routed).is_ok());
    }

    // RFC 3261 sections 8.1.1.7 and 25.1. A branch is a token, starts with the
    // magic cookie in its exact case, and identifies something after it.
    #[test]
    fn a_branch_is_a_token_after_the_magic_cookie() {
        let longest = "z9hG4bKx".repeat(MAX_BRANCH / 8);
        for valid in ["z9hG4bK1", "z9hG4bK-proxy.a1_~!%*+`'", longest.as_str()]
        {
            assert_eq!(valid.parse::<Branch>().unwrap().as_str(), valid);
        }

        for invalid in [
            "",
            "z9hG4bK",
            "Z9HG4BK1",
            "1z9hG4bK",
            "z9hG4bK a",
            "z9hG4bK1;received=192.0.2.1",
            "z9hG4bK1,SIP/2.0/UDP evil.example.com",
            "z9hG4bK1\r\nTo: x",
            "z9hG4bK\"1\"",
            format!("{longest}x").as_str(),
        ] {
            assert!(invalid.parse::<Branch>().is_err(), "{invalid:?}");
        }
    }
}
