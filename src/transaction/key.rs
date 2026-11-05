/*!
Matching messages to transactions, RFC 3261 sections 17.1.3 and 17.2.3.
*/

use std::hash::{Hash, Hasher};

use bytes::Bytes;

use super::super::header::{cseq::CSeq, via::Via, HeaderValue, VIA};
use crate::{header::CSEQ, Method, Request, Response};

/// The magic cookie that starts every branch an RFC 3261 element makes.
const COOKIE: &str = "z9hG4bK";

/// What identifies a server transaction.
///
/// RFC 3261 section 17.2.3 matches a request to a server transaction by the
/// `branch` and `sent-by` of its top `Via` and its method. Only a branch that
/// starts with the magic cookie counts. The RFC 2543 rules for other branches
/// are not supported, so a request without the cookie matches no transaction
/// and starts none. A retransmission of it is handed up again.
///
/// The branch compares byte for byte after the cookie, since the same element
/// made it each time. The host of `sent-by` compares without regard to ASCII
/// case, as a hostname does. The hash covers the branch and the method only,
/// which keeps equal keys hashing alike.
#[derive(Clone, Debug)]
pub struct ServerKey {
    branch: Bytes,
    host: Bytes,
    port: Option<u16>,
    method: Method,
}

impl ServerKey {
    /// Returns the key of `request`, or `None` if its top `Via` is missing,
    /// unreadable, or has no RFC 3261 branch.
    ///
    /// The endpoint has parsed the `Via` already when it needs the key, so it
    /// uses [`ServerKey::new`]. This is for tests and benchmarks.
    #[cfg_attr(not(any(test, feature = "__bench")), allow(dead_code))]
    pub fn from_request(request: &Request<Bytes>) -> Option<ServerKey> {
        let value = request.headers().get(VIA)?;
        let via = Via::top(value)?;

        ServerKey::new(value, &via, request.method())
    }

    /// Returns the key for a request whose top `Via` the caller has parsed
    /// from `value` already, or `None` if it has no RFC 3261 branch.
    pub fn new(
        value: &HeaderValue,
        via: &Via<'_>,
        method: &Method,
    ) -> Option<ServerKey> {
        let branch = branch(value, via)?;

        Some(ServerKey {
            branch,
            host: value.as_shared().slice_ref(via.host.as_bytes()),
            port: via.port,
            method: method.clone(),
        })
    }
}

impl PartialEq for ServerKey {
    fn eq(&self, other: &ServerKey) -> bool {
        self.branch == other.branch
            && self.port == other.port
            && self.method == other.method
            && self.host.eq_ignore_ascii_case(&other.host)
    }
}

impl Eq for ServerKey {}

impl Hash for ServerKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.branch.hash(state);
        self.method.hash(state);
    }
}

/// What matches a response to a client transaction.
///
/// RFC 3261 section 17.1.3 matches a response by the `branch` of its top
/// `Via`, which the client put there, and the method in its `CSeq`. The key
/// of the transaction comes from the request with [`ClientKey::from_request`],
/// and the key to look up comes from the response with
/// [`ClientKey::from_response`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientKey {
    branch: Bytes,
    method: Method,
}

impl ClientKey {
    /// Returns the key of a request this element sends, or `None` if its top
    /// `Via` is missing, unreadable, or has no RFC 3261 branch.
    pub fn from_request(request: &Request<Bytes>) -> Option<ClientKey> {
        let value = request.headers().get(VIA)?;
        let branch = branch(value, &Via::top(value)?)?;

        Some(ClientKey { branch, method: request.method().clone() })
    }

    /// Returns the key a response matches, or `None` if its top `Via` or
    /// `CSeq` is missing or unreadable, or the branch has no cookie.
    pub fn from_response(response: &Response<Bytes>) -> Option<ClientKey> {
        let value = response.headers().get(VIA)?;
        let branch = branch(value, &Via::top(value)?)?;
        let cseq = CSeq::parse(response.headers().get(CSEQ)?)?;

        Some(ClientKey { branch, method: cseq.method })
    }
}

/// Returns the branch of `via` as a slice of `value`, if it has the cookie.
///
/// The cookie is a token, which RFC 3261 section 7.3.1 compares without regard
/// to case. The rest of the branch is kept as written.
fn branch(value: &HeaderValue, via: &Via<'_>) -> Option<Bytes> {
    let branch = via.branch?;
    let cookie = branch.get(..COOKIE.len())?;
    if !cookie.eq_ignore_ascii_case(COOKIE) {
        return None;
    }

    Some(value.as_shared().slice_ref(branch.as_bytes()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn request(head: &str) -> Request<Bytes> {
        Request::from_bytes(format!("{head}\r\n").as_bytes()).unwrap()
    }

    fn response(head: &str) -> Response<Bytes> {
        Response::from_bytes(format!("{head}\r\n").as_bytes()).unwrap()
    }

    const OPTIONS: &str = "OPTIONS sip:carol@chicago.example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP PC33.atlanta.example.com:5060;branch=z9hG4bKhjhs8ass877;rport\r\n\
        Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bKother\r\n\
        CSeq: 63104 OPTIONS\r\n";

    #[test]
    fn server_keys_match_retransmissions_and_tell_transactions_apart() {
        let key = ServerKey::from_request(&request(OPTIONS)).unwrap();
        assert_eq!(key.branch, "z9hG4bKhjhs8ass877");
        assert_eq!(key.host, "PC33.atlanta.example.com");
        assert_eq!(key.port, Some(5060));
        assert_eq!(key.method, Method::OPTIONS);

        let same = ServerKey::from_request(&request(
            "OPTIONS sip:other@example.com SIP/2.0\r\n\
             v: SIP/2.0/UDP pc33.ATLANTA.example.com:5060;branch=z9hG4bKhjhs8ass877\r\n\
             CSeq: 2 OPTIONS\r\n",
        ))
        .unwrap();
        assert_eq!(key, same);
        let mut set = HashSet::new();
        set.insert(key.clone());
        assert!(set.contains(&same));

        for other in [
            "OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP PC33.atlanta.example.com:5060;branch=z9hG4bKhjhs8ass878\r\n",
            "OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP PC33.atlanta.example.com:5060;branch=Z9HG4BKhjhs8ass877\r\n",
            "OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP PC33.atlanta.example.com;branch=z9hG4bKhjhs8ass877\r\n",
            "OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP PC33.atlanta.example.com:5061;branch=z9hG4bKhjhs8ass877\r\n",
            "OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP pc34.atlanta.example.com:5060;branch=z9hG4bKhjhs8ass877\r\n",
            "REGISTER sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP PC33.atlanta.example.com:5060;branch=z9hG4bKhjhs8ass877\r\n",
        ] {
            let other = ServerKey::from_request(&request(other)).unwrap();
            assert_ne!(key, other, "{other:?}");
        }
    }

    #[test]
    fn the_cookie_is_case_insensitive() {
        let request = request(
            "OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP a.example.com;branch=Z9HG4BK1\r\n",
        );
        assert!(ServerKey::from_request(&request).is_some());
        assert!(ClientKey::from_request(&request).is_some());
    }

    #[test]
    fn requests_without_an_rfc_3261_branch_have_no_key() {
        for head in [
            "OPTIONS sip:a@b SIP/2.0\r\nCSeq: 1 OPTIONS\r\n",
            "OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP a.example.com\r\n",
            "OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP a.example.com;branch=1\r\n",
            "OPTIONS sip:a@b SIP/2.0\r\nVia: broken\r\n",
        ] {
            let request = request(head);
            assert!(ServerKey::from_request(&request).is_none(), "{head:?}");
            assert!(ClientKey::from_request(&request).is_none(), "{head:?}");
        }
    }

    #[test]
    fn client_keys_match_a_response_to_its_request() {
        let key = ClientKey::from_request(&request(OPTIONS)).unwrap();
        assert_eq!(key.branch, "z9hG4bKhjhs8ass877");
        assert_eq!(key.method, Method::OPTIONS);

        let found = ClientKey::from_response(&response(
            "SIP/2.0 200 OK\r\n\
             Via: SIP/2.0/UDP PC33.atlanta.example.com:5060;branch=z9hG4bKhjhs8ass877;rport=5060;received=192.0.2.4\r\n\
             Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bKother\r\n\
             CSeq: 63104 OPTIONS\r\n",
        ))
        .unwrap();
        assert_eq!(key, found);

        let other_method = ClientKey::from_response(&response(
            "SIP/2.0 200 OK\r\n\
             Via: SIP/2.0/UDP PC33.atlanta.example.com:5060;branch=z9hG4bKhjhs8ass877\r\n\
             CSeq: 63104 REGISTER\r\n",
        ))
        .unwrap();
        assert_ne!(key, other_method);
    }

    #[test]
    fn responses_without_a_branch_or_cseq_have_no_key() {
        for head in [
            "SIP/2.0 200 OK\r\nCSeq: 1 OPTIONS\r\n",
            "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP a.example.com;branch=z9hG4bK1\r\n",
            "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP a.example.com;branch=z9hG4bK1\r\nCSeq: x\r\n",
            "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP a.example.com;branch=1\r\nCSeq: 1 OPTIONS\r\n",
        ] {
            assert!(ClientKey::from_response(&response(head)).is_none(), "{head:?}");
        }
    }

    #[test]
    fn keys_share_the_message_buffer() {
        let request = request(OPTIONS);
        let key = ServerKey::from_request(&request).unwrap();
        let value = request.headers().get(VIA).unwrap();
        let range = value.as_bytes().as_ptr_range();
        assert!(range.contains(&key.branch.as_ptr()));
        assert!(range.contains(&key.host.as_ptr()));
    }
}
