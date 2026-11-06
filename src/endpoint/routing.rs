/*!
Via construction, source selection and response destinations.

The driver owns transaction and connection lifetimes. This module applies
[RFC 3261 sections 18.1 and 18.2] and [RFC 3581 section 4] to the transport
metadata it gets. It preserves the original TCP writer even when the fallback
destination differs from the received flow.

[RFC 3261 sections 18.1 and 18.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18
[RFC 3581 section 4]: https://www.rfc-editor.org/rfc/rfc3581.html#section-4
*/

use std::{
    collections::hash_map::RandomState,
    fmt::Write as _,
    hash::{BuildHasher, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::{
    message::header::{via::Via, HeaderValue},
    transport::{tcp, Flow},
};

/// The port `sent-by` means when it names none (RFC 3261 section 18.2.2).
const DEFAULT_PORT: u16 = 5060;

/// A way to send: the flow, and the connection when the flow is TCP.
#[derive(Clone)]
pub(super) struct Link {
    pub(super) flow: Flow,
    pub(super) writer: Option<tcp::Writer>,
}

/// Makes branches. Each is the magic cookie, a random prefix taken once, and
/// a counter, so no two transactions of this endpoint share one, and no two
/// endpoints do either, in all likelihood. Neither a syscall nor a random
/// number is needed per request.
pub(super) struct Branches {
    prefix: String,
    next: u64,
}

impl Branches {
    pub(super) fn new() -> Branches {
        // The standard library seeds its hasher randomly. Hashing nothing with
        // a fresh one gives 64 random bits without another dependency.
        let mut seed = RandomState::new().build_hasher().finish();
        let mut prefix = String::from("z9hG4bK");
        for _ in 0..10 {
            let digit = (seed % 36) as u8;
            seed /= 36;
            prefix.push(char::from(if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            }));
        }

        Branches { prefix, next: 0 }
    }
}

/// Asks the kernel which address it would send to `remote` from.
pub(super) fn source_toward(remote: SocketAddr) -> io::Result<IpAddr> {
    let any = match remote {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let probe = std::net::UdpSocket::bind(SocketAddr::new(any, 0))?;
    probe.connect(remote)?;

    Ok(probe.local_addr()?.ip())
}

/// The `Via` this endpoint puts on a request it sends on `flow`.
///
/// `rport` asks the server to answer the port the request came from
/// (RFC 3581), which is what a NAT lets through.
pub(super) fn via_value(flow: &Flow, branches: &mut Branches) -> HeaderValue {
    let mut value = String::with_capacity(80);
    let n = branches.next;
    branches.next += 1;
    let _ = write!(
        value,
        "SIP/2.0/{} {};rport;branch={}{n:x}",
        flow.transport, flow.local, branches.prefix
    );

    HeaderValue::from_built(value)
}

/// Returns `true` if the `sent-by` of `via` is `local`.
pub(super) fn sent_by_is(via: &Via<'_>, local: SocketAddr) -> bool {
    via.host.parse::<IpAddr>().is_ok_and(|ip| ip == local.ip())
        && via.port.unwrap_or(DEFAULT_PORT) == local.port()
}

/// Where a response to a request received on `flow` with the top `via` goes
/// (RFC 3261 section 18.2.2, RFC 3581 section 4).
///
/// It goes to the address the request came from, which is what `received`
/// would say, since the endpoint adds that parameter whenever `sent-by` says
/// otherwise. Nothing here trusts a `received` the request came with, so a
/// request cannot have its response sent to a third party.
///
/// Over UDP the port is the source port with `rport`, and the `sent-by` port
/// without it. Over TCP the response goes back on the connection, and the
/// flow's remote address is where a new connection goes when that one has
/// closed. That is the `sent-by` port, since RFC 3581 applies `rport` to
/// unreliable transports only.
pub(super) fn reply_flow(via: &Via<'_>, flow: &Flow) -> Flow {
    let port = match via.rport {
        Some(_) if !flow.transport.is_reliable() => flow.remote.port(),
        _ => via.port.unwrap_or(DEFAULT_PORT),
    };

    Flow { remote: SocketAddr::new(flow.remote.ip(), port), ..*flow }
}

/// Returns the top `Via` with `received` and `rport` filled in, or `None` when
/// neither is called for.
///
/// `received` is added at the end of the first `via-parm` when `sent-by` names
/// a host other than the source address (RFC 3261 section 18.2.1). A valueless
/// `rport` is given the source port in place (RFC 3581 section 4). An `rport`
/// that came with a value is left alone. The response goes to the source port
/// either way, see [`reply_flow`].
pub(super) fn mark_via(
    value: &HeaderValue,
    via: &Via<'_>,
    flow: &Flow,
) -> Option<HeaderValue> {
    let source = flow.remote;
    let received =
        via.host.parse::<IpAddr>().map_or(true, |host| host != source.ip());
    if !received && via.rport_at.is_none() {
        return None;
    }

    let src = value.as_str();
    let mut marked = String::with_capacity(src.len() + 40);
    let mut copied = 0;
    if let Some(at) = via.rport_at {
        marked.push_str(&src[..at]);
        let _ = write!(marked, "={}", source.port());
        copied = at;
    }
    marked.push_str(&src[copied..via.end]);
    if received {
        let _ = write!(marked, ";received={}", source.ip());
    }
    marked.push_str(&src[via.end..]);

    Some(HeaderValue::from_built(marked))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Transport;

    #[test]
    fn reply_ports_follow_transport_and_rport_without_trusting_received() {
        for (transport, remote, via, port) in [
            (
                Transport::Udp,
                "192.0.2.1:40000",
                "SIP/2.0/UDP example.com;rport;received=198.51.100.9",
                40000,
            ),
            (
                Transport::Udp,
                "192.0.2.1:40000",
                "SIP/2.0/UDP example.com",
                5060,
            ),
            (
                Transport::Tcp,
                "192.0.2.1:40000",
                "SIP/2.0/TCP example.com:5070;rport=1234",
                5070,
            ),
            (
                Transport::Udp,
                "[2001:db8::1]:40000",
                "SIP/2.0/UDP [2001:db8::2]:5070",
                5070,
            ),
        ] {
            let value = HeaderValue::from_bytes(via.as_bytes()).unwrap();
            let via = Via::top(&value).unwrap();
            let local = if remote.starts_with('[') {
                "[2001:db8::2]:5060"
            } else {
                "192.0.2.2:5060"
            };
            let flow = Flow {
                transport,
                local: local.parse().unwrap(),
                remote: remote.parse().unwrap(),
            };

            let reply = reply_flow(&via, &flow);

            assert_eq!(reply.remote.ip(), flow.remote.ip());
            assert_eq!(reply.remote.port(), port);
            assert_eq!(reply.local, flow.local);
            assert_eq!(reply.transport, flow.transport);
        }
    }

    #[test]
    fn marking_the_top_via_preserves_later_values() {
        let value = HeaderValue::from_static(concat!(
            "SIP/2.0/UDP example.com:5070;rport;branch=z9hG4bKfirst, ",
            "SIP/2.0/UDP older.example.com;branch=z9hG4bKsecond",
        ));
        let via = Via::top(&value).unwrap();
        let flow = Flow {
            transport: Transport::Udp,
            local: "192.0.2.2:5060".parse().unwrap(),
            remote: "192.0.2.1:40000".parse().unwrap(),
        };

        let marked = mark_via(&value, &via, &flow).unwrap();

        assert_eq!(
            marked,
            concat!(
                "SIP/2.0/UDP example.com:5070;rport=40000;branch=z9hG4bKfirst",
                ";received=192.0.2.1, ",
                "SIP/2.0/UDP older.example.com;branch=z9hG4bKsecond",
            )
        );
    }
}
