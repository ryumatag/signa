/*!
Requests sent once, outside any transaction.

[`Endpoint::send_request`] is the transport operation of the 0.3.0 design. A
stateful endpoint takes it for the ACK a UAC core sends for each 2xx
([RFC 3261 section 13.2.2.4]), which no transaction carries. Its other uses,
a caller-selected branch and other methods for stateless forwarding, come with
stateless reception.

[RFC 3261 section 13.2.2.4]: https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4
*/

use std::future::Future;

use bytes::Bytes;
use tokio::sync::oneshot;

use super::{
    client::Target, driver::Command, reply::Completion, Endpoint, Error,
};
use crate::{
    message::{
        header::{cseq::CSeq, HeaderValue, CSEQ},
        Method, Request,
    },
    transport::{Flow, Transport},
};

/// Room the reservation of a request leaves for the Via the driver adds.
///
/// The Via is `SIP/2.0/UDP`, a `sent-by` of at most an IPv6 address with a
/// scope and a port, `;rport;branch=`, the 17-byte branch prefix and a 64-bit
/// counter in hex, with its name and line end. That is under 140 bytes.
const VIA_ALLOWANCE: usize = 160;

/// How [`Endpoint::send_request`] makes the Via it prepends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ViaMode {
    /// A Via with a fresh branch, as a UAC core's ACK for a 2xx needs. The ACK
    /// is a transaction of its own ([RFC 3261 section 17.1.1.3]).
    ///
    /// [RFC 3261 section 17.1.1.3]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.3
    Fresh,
}

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
    /// The endpoint prepends one Via as `via` says, and sends the request
    /// once, with no retransmission and no response observation. For now
    /// the request must be an ACK, which the TU builds for a 2xx from its
    /// dialog, sends to the target it chose, and repeats for each
    /// retransmitted 2xx ([RFC 3261 section 13.2.2.4]). The 2xx itself
    /// arrives through the INVITE's [`Responses`](super::Responses). A
    /// non-2xx ACK is the transaction's and never goes through here.
    ///
    /// Routing is the caller's, as for [`Endpoint::start`]. The only check
    /// refuses a `sips:` Request-URI. Route and `target` are sent as given,
    /// and a request that needs TLS must not be sent through this endpoint.
    /// A UDP request above 1300 bytes is refused, as
    /// [RFC 3261 section 18.1.1] asks.
    ///
    /// An ACK can be sent while the endpoint shuts down, since a 2xx can
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
    /// * [`Error::is_unsupported_method`] for anything but ACK.
    /// * [`Error::is_invalid_cseq`] unless the request has one CSeq with the
    ///   ACK method. A request without CSeq gets an error naming it.
    /// * [`Error::is_unsupported_routing`] for a `sips:` Request-URI, a
    ///   multicast target, or a UDP target on an endpoint without a UDP
    ///   socket.
    /// * [`Error::is_too_large`] for a UDP request over 1300 bytes.
    /// * [`Error::is_busy`] when the one-shot byte budget,
    ///   [`Builder::max_reply_bytes`], or the connection limits are full.
    /// * [`Error::is_transport`] when a connection or the write fails.
    /// * [`Error::is_closed`] once the endpoint has stopped.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bytes::Bytes;
    /// use signa::{
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
    /// [RFC 3261 section 18.1.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.1.1
    /// [`Builder::max_reply_bytes`]: super::Builder::max_reply_bytes
    #[allow(clippy::manual_async_fn)] // Expose the Send guarantee on Rust 1.71.
    pub fn send_request(
        &self,
        request: Request<Bytes>,
        target: Target,
        via: ViaMode,
    ) -> impl Future<Output = Result<SentRequest, Error>> + Send + '_ {
        async move {
            let ViaMode::Fresh = via;
            validate(&request)?;
            if target.address().ip().is_multicast()
                || (target.transport() == Transport::Udp && self.udp.is_none())
            {
                return Err(Error::unsupported_routing());
            }
            if self.commands.is_closed() {
                return Err(Error::closed());
            }
            let len = request
                .encoded_len()
                .and_then(|len| len.checked_add(VIA_ALLOWANCE))
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
    if request.method() != Method::ACK {
        return Err(Error::unsupported_method());
    }

    let mut values = request.headers().get_all(CSEQ);
    let value = values.next().ok_or_else(|| Error::missing(CSEQ))?;
    if values.next().is_some()
        || !CSeq::parse(value).is_some_and(|cseq| cseq.method == Method::ACK)
    {
        return Err(Error::invalid_cseq());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, uri: &str, cseq: &str) -> Request<Bytes> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("CSeq", cseq)
            .body(Bytes::new())
            .unwrap()
    }

    // signa's scope for this item, not an RFC rule. Other methods and
    // caller-selected branches come with stateless forwarding.
    #[test]
    fn only_an_ack_with_its_cseq_and_a_sip_uri_is_sent() {
        assert!(
            validate(&request("ACK", "sip:bob@example.com", "1 ACK")).is_ok()
        );

        for method in ["INVITE", "OPTIONS", "CANCEL", "BYE", "ack"] {
            let error =
                validate(&request(method, "sip:bob@example.com", "1 ACK"))
                    .unwrap_err();
            assert!(error.is_unsupported_method(), "{method}");
        }
        for uri in ["sips:bob@example.com", "SIPS:bob@example.com"] {
            let error = validate(&request("ACK", uri, "1 ACK")).unwrap_err();
            assert!(error.is_unsupported_routing(), "{uri}");
        }
        for cseq in ["1 INVITE", "x ACK", "1 ACK, 2 ACK"] {
            let error = validate(&request("ACK", "sip:bob@example.com", cseq))
                .unwrap_err();
            assert!(error.is_invalid_cseq(), "{cseq}");
        }
    }
}
