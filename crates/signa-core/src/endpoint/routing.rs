/*!
Via construction, source selection and response destinations.

The driver owns transaction and connection lifetimes. This module applies
[RFC 3261 sections 18.1 and 18.2] and [RFC 3581 section 4] to the transport
metadata it gets. It preserves the original TCP writer even when the fallback
destination differs from the received flow.

A response has two kinds of destination. One to a request this endpoint
received goes where the request came from, see [`reply_flow`]. One that a
stateless proxy forwards goes where its remaining top Via says, see
[`forward_destination`], since the proxy never saw that request's source
itself. The two share the Via parser and the default port, not the rule.

[RFC 3261 sections 18.1 and 18.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18
[RFC 3581 section 4]: https://www.rfc-editor.org/rfc/rfc3581.html#section-4
*/

use std::{
    collections::hash_map::RandomState,
    fmt::Write as _,
    hash::{BuildHasher, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use super::Error;
use crate::{
    message::header::{HeaderValue, VIA, via::Via},
    transport::{Flow, Transport, datagram::Path, tcp},
};

/// The port `sent-by` means when it names none (RFC 3261 section 18.2.2).
const DEFAULT_PORT: u16 = 5060;

/// A way to send: the flow, the connection when the flow is TCP, and the
/// backend's path when one was received or prepared.
///
/// The path is `None` for TCP and for every datagram of the endpoint's own
/// socket, so cloning a link costs those nothing more than before.
#[derive(Clone)]
pub(super) struct Link {
    pub(super) flow: Flow,
    pub(super) writer: Option<tcp::Writer>,
    pub(super) path: Option<Arc<Path>>,
}

impl Link {
    /// The `sent-by` a request on this link advertises: its prepared path's,
    /// or [`sent_by`] of its flow.
    pub(super) fn sent_by(&self, listener: Option<SocketAddr>) -> SocketAddr {
        match self.path.as_deref().and_then(|path| path.prepared.as_deref()) {
            Some(prepared) => prepared.sent_by,
            None => sent_by(&self.flow, listener),
        }
    }
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

/// The `sent-by` this endpoint puts in the `Via` of a request it sends on
/// `flow`, given the address of its TCP listener.
///
/// A client on a reliable transport must accept a connection on the `sent-by`
/// port, because a server whose connection has closed opens a new one there
/// for the response ([RFC 3261 sections 18.1.1 and 18.2.2]). The local port of
/// an outbound TCP connection is ephemeral and nothing listens on it. So when
/// the listener accepts connections on the connection's local address, the
/// `sent-by` is that address with the listener's port. Otherwise it is the
/// flow's own local address, and no response reaches the client once its
/// connection has closed.
///
/// I only advertise a listener of the same address family. A dual-stack IPv6
/// listener may accept IPv4 connections, but that depends on a socket option
/// the endpoint does not control.
///
/// [RFC 3261 sections 18.1.1 and 18.2.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.1.1
pub(super) fn sent_by(
    flow: &Flow,
    listener: Option<SocketAddr>,
) -> SocketAddr {
    match listener {
        Some(listener)
            if flow.transport == Transport::Tcp
                && listener.is_ipv4() == flow.local.is_ipv4()
                && (listener.ip().is_unspecified()
                    || listener.ip() == flow.local.ip()) =>
        {
            SocketAddr::new(flow.local.ip(), listener.port())
        }
        _ => flow.local,
    }
}

/// The `Via` this endpoint puts on a request it sends over `transport`, with
/// `sent_by` from [`sent_by`].
///
/// `rport` asks the server to answer the port the request came from
/// (RFC 3581), which is what a NAT lets through.
pub(super) fn via_value(
    transport: Transport,
    sent_by: SocketAddr,
    branches: &mut Branches,
) -> HeaderValue {
    let mut value = String::with_capacity(80);
    let n = branches.next;
    branches.next += 1;
    let _ = write!(
        value,
        "SIP/2.0/{transport} {sent_by};rport;branch={}{n:x}",
        branches.prefix
    );

    HeaderValue::from_built(value)
}

/// As [`via_value`], with a branch the caller chose and validated.
pub(super) fn via_value_with(
    transport: Transport,
    sent_by: SocketAddr,
    branch: &str,
) -> HeaderValue {
    let mut value = String::with_capacity(48 + branch.len());
    let _ =
        write!(value, "SIP/2.0/{transport} {sent_by};rport;branch={branch}");

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
/// a host other than the source address (RFC 3261 section 18.2.1), or when the
/// parm already has a `received` that signa did not write. A valueless
/// `rport` is given the source port in place, and then `received` is added
/// even when it equals the host, as RFC 3581 section 4 requires. A proxy that
/// forwards the response later routes by the pair, see
/// [`forward_destination`]. An `rport` that came with a value is left alone.
/// The response to this request goes to the source port either way, see
/// [`reply_flow`].
pub(super) fn mark_via(
    value: &HeaderValue,
    via: &Via<'_>,
    flow: &Flow,
) -> Option<HeaderValue> {
    let source = flow.remote;
    // A `received` the sender wrote itself is outvoted by one appended after
    // it, see `Via::received`.
    let received = via.rport_at.is_some()
        || via.received.is_some()
        || via.host.parse::<IpAddr>().map_or(true, |host| host != source.ip());
    if !received {
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
    let _ = write!(marked, ";received={}", source.ip());
    marked.push_str(&src[via.end..]);

    Some(HeaderValue::from_built(marked))
}

/// Where a stateless proxy sends a response it forwards, from the response's
/// top `Via` once the TU has removed its own ([RFC 3261 section 16.11]).
///
/// Only an unreliable unicast reply is supported. The rules are those of
/// [RFC 3261 section 18.2.2] for UDP and [RFC 3581 section 4]:
///
/// * With `received`, the response goes to that address, and to the port of
///   `rport` when it has one. Otherwise it goes to the `sent-by` port, or
///   5060 without one.
/// * Without `received`, `sent-by` must be an IP address, and the response
///   goes to its port or 5060. An `rport` without `received` is not one a
///   server filled in, so it does not count.
///
/// Anything else is an error without a send. A transport other than UDP needs
/// the original connection or RFC 3263 to find one, `maddr` names a multicast
/// group, and a host name needs a DNS lookup, all of which are out of scope.
/// A multicast or unspecified address is refused as well. A `received` that
/// is not an IP address, or a port of zero, makes the `Via` invalid.
///
/// [RFC 3261 section 16.11]: https://www.rfc-editor.org/rfc/rfc3261.html#section-16.11
/// [RFC 3261 section 18.2.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2
/// [RFC 3581 section 4]: https://www.rfc-editor.org/rfc/rfc3581.html#section-4
pub(super) fn forward_destination(via: &Via<'_>) -> Result<SocketAddr, Error> {
    if !via.transport.eq_ignore_ascii_case("UDP") || via.maddr.is_some() {
        return Err(Error::unsupported_routing());
    }

    let (ip, port) = match via.received {
        Some(received) => {
            let ip = received
                .parse::<IpAddr>()
                .map_err(|_| Error::invalid_header(VIA))?;
            let port = match via.rport {
                Some(Some(port)) => port,
                _ => via.port.unwrap_or(DEFAULT_PORT),
            };
            (ip, port)
        }
        None => {
            let ip = via
                .host
                .parse::<IpAddr>()
                .map_err(|_| Error::unsupported_routing())?;
            (ip, via.port.unwrap_or(DEFAULT_PORT))
        }
    };

    if port == 0 {
        return Err(Error::invalid_header(VIA));
    }
    if ip.is_multicast() || ip.is_unspecified() {
        return Err(Error::unsupported_routing());
    }
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn sent_by_names_a_listener_that_accepts_on_the_connection_s_address() {
        for (transport, local, listener, sent_by) in [
            (Transport::Tcp, "192.0.2.2:49152", None, "192.0.2.2:49152"),
            (
                Transport::Tcp,
                "192.0.2.2:49152",
                Some("0.0.0.0:5060"),
                "192.0.2.2:5060",
            ),
            (
                Transport::Tcp,
                "192.0.2.2:49152",
                Some("192.0.2.2:5070"),
                "192.0.2.2:5070",
            ),
            // A listener on another address cannot take the connection.
            (
                Transport::Tcp,
                "192.0.2.2:49152",
                Some("192.0.2.3:5060"),
                "192.0.2.2:49152",
            ),
            // Nor can one of another family, whatever its dual-stack setting.
            (
                Transport::Tcp,
                "192.0.2.2:49152",
                Some("[::]:5060"),
                "192.0.2.2:49152",
            ),
            (
                Transport::Tcp,
                "[2001:db8::2]:49152",
                Some("[::]:5060"),
                "[2001:db8::2]:5060",
            ),
            // UDP answers the socket itself.
            (
                Transport::Udp,
                "192.0.2.2:5062",
                Some("0.0.0.0:5060"),
                "192.0.2.2:5062",
            ),
        ] {
            let flow = Flow {
                transport,
                local: local.parse().unwrap(),
                remote: "192.0.2.1:5060".parse().unwrap(),
            };
            let listener = listener.map(|addr| addr.parse().unwrap());

            assert_eq!(
                super::sent_by(&flow, listener),
                sent_by.parse::<SocketAddr>().unwrap(),
                "{local} with {listener:?}"
            );
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

    // RFC 3581 section 4. A server that fills in `rport` adds `received` even
    // when it equals the `sent-by` host. A `received` the sender wrote is
    // outvoted by the one appended after it.
    #[test]
    fn rport_and_a_sender_s_received_always_get_the_source_address() {
        let flow = Flow {
            transport: Transport::Udp,
            local: "192.0.2.2:5060".parse().unwrap(),
            remote: "192.0.2.1:40000".parse().unwrap(),
        };
        for (via, marked) in [
            (
                "SIP/2.0/UDP 192.0.2.1:5060;rport;branch=z9hG4bKa",
                Some(
                    "SIP/2.0/UDP 192.0.2.1:5060;rport=40000;branch=z9hG4bKa\
                     ;received=192.0.2.1",
                ),
            ),
            (
                "SIP/2.0/UDP 192.0.2.1:40000;received=198.51.100.7\
                 ;branch=z9hG4bKa",
                Some(
                    "SIP/2.0/UDP 192.0.2.1:40000;received=198.51.100.7\
                     ;branch=z9hG4bKa;received=192.0.2.1",
                ),
            ),
            ("SIP/2.0/UDP 192.0.2.1:40000;branch=z9hG4bKa", None),
        ] {
            let value = HeaderValue::from_bytes(via.as_bytes()).unwrap();
            let parsed = Via::top(&value).unwrap();

            let result = mark_via(&value, &parsed, &flow);

            assert_eq!(
                result.as_ref().map(HeaderValue::as_str),
                marked,
                "{via}"
            );
            if let Some(result) = result {
                assert_eq!(
                    Via::top(&result).unwrap().received,
                    Some("192.0.2.1")
                );
            }
        }
    }

    // RFC 3261 section 18.2.2 for unreliable unicast, with RFC 3581 section 4.
    #[test]
    fn a_forwarded_response_goes_where_its_remaining_top_via_says() {
        for (via, destination) in [
            ("SIP/2.0/UDP 192.0.2.1:5070;branch=z9hG4bKa", "192.0.2.1:5070"),
            ("SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKa", "192.0.2.1:5060"),
            ("sip/2.0/udp 192.0.2.1;branch=z9hG4bKa", "192.0.2.1:5060"),
            (
                "SIP/2.0/UDP pc33.example.com:5070;received=192.0.2.9",
                "192.0.2.9:5070",
            ),
            (
                "SIP/2.0/UDP pc33.example.com;received=192.0.2.9",
                "192.0.2.9:5060",
            ),
            (
                "SIP/2.0/UDP pc33.example.com:5070;rport=40000\
                 ;received=192.0.2.9",
                "192.0.2.9:40000",
            ),
            // Without `received`, `rport` does not count.
            ("SIP/2.0/UDP 192.0.2.1:5070;rport=40000", "192.0.2.1:5070"),
            ("SIP/2.0/UDP 192.0.2.1:5070;rport", "192.0.2.1:5070"),
            (
                "SIP/2.0/UDP [2001:db8::1]:5070;branch=z9hG4bKa",
                "[2001:db8::1]:5070",
            ),
            (
                "SIP/2.0/UDP [2001:db8::1];branch=z9hG4bKa",
                "[2001:db8::1]:5060",
            ),
            (
                "SIP/2.0/UDP host.example.com;rport=40000\
                 ;received=2001:db8::9",
                "[2001:db8::9]:40000",
            ),
            // Only the first value of a row is the top Via.
            (
                "SIP/2.0/UDP 192.0.2.1:5070, SIP/2.0/UDP 192.0.2.2:5080",
                "192.0.2.1:5070",
            ),
        ] {
            let value = HeaderValue::from_bytes(via.as_bytes()).unwrap();
            let via = Via::top(&value).unwrap();

            assert_eq!(
                forward_destination(&via).unwrap(),
                destination.parse::<SocketAddr>().unwrap(),
                "{}",
                value.as_str()
            );
        }
    }

    // signa's scope, not an RFC rule. What would need DNS, a connection,
    // multicast or nothing at all is refused rather than guessed.
    #[test]
    fn a_forwarded_response_signa_cannot_route_is_refused() {
        for via in [
            "SIP/2.0/UDP pc33.example.com:5070",
            "SIP/2.0/UDP pc33.example.com;rport=40000",
            "SIP/2.0/TCP 192.0.2.1:5070",
            "SIP/2.0/TLS 192.0.2.1:5061",
            "SIP/2.0/SCTP 192.0.2.1:5070",
            "SIP/2.0/UDP 192.0.2.1;maddr=224.0.1.75;ttl=1",
            "SIP/2.0/UDP 224.0.1.75",
            "SIP/2.0/UDP pc33.example.com;received=224.0.1.75",
            "SIP/2.0/UDP 0.0.0.0:5060",
            "SIP/2.0/UDP [::]:5060",
        ] {
            let value = HeaderValue::from_bytes(via.as_bytes()).unwrap();
            let error =
                forward_destination(&Via::top(&value).unwrap()).unwrap_err();
            assert!(error.is_unsupported_routing(), "{via}: {error}");
        }

        for via in [
            "SIP/2.0/UDP pc33.example.com;received=1.2.3",
            "SIP/2.0/UDP 192.0.2.1:0",
            "SIP/2.0/UDP pc33.example.com;received=192.0.2.9;rport=0",
        ] {
            let value = HeaderValue::from_bytes(via.as_bytes()).unwrap();
            let error =
                forward_destination(&Via::top(&value).unwrap()).unwrap_err();
            assert!(error.is_invalid_header(), "{via}: {error}");
        }
    }
}
