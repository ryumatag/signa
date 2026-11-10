/*!
Route sets, remote targets, and where a request in a dialog goes.

A dialog keeps two routing values apart, as RFC 3261 section 12.2 does. The
route set comes from Record-Route when the dialog forms and never changes
after it is confirmed. The remote target comes from Contact and moves with
each target refresh. [`request_target`] turns the two into the Request-URI
and Route values of a request (RFC 3261 section 12.2.1.1), and names the URI
whose address the request goes to (RFC 3261 section 8.1.2).

That URI is then resolved to a transport and a socket address. Here that is
[`StaticResolver`], which takes IP literals and an explicit table of host
names and nothing else. It does no DNS, so it does not implement RFC 3263, and
it refuses a host name it has no entry for rather than guess. The address a
response came from is never a destination, since the dialog's own routing
values say where its requests go.

[`request_target`]: crate::routing::request_target
*/

use std::{
    collections::HashMap,
    error, fmt,
    net::{IpAddr, SocketAddr},
};

use signa_core::{
    HeaderMap,
    message::{
        header::{RECORD_ROUTE, ROUTE},
        uri::{Scheme, SipUri},
    },
    transport::Transport,
};

use crate::protocol::{Field, Malformed, addresses};

/// One URI of a route set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Route {
    /// The URI as received, with all its parameters, as RFC 3261 sections
    /// 12.1.1 and 12.1.2 require.
    uri: Box<str>,
    /// Whether the URI has `lr`, marking a loose router (RFC 3261 section
    /// 19.1.1).
    loose: bool,
}

impl Route {
    pub(crate) fn uri(&self) -> &str {
        &self.uri
    }
}

/// The route set of a dialog, in the order requests visit it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RouteSet(Box<[Route]>);

/// The order in which Record-Route values become a route set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Order {
    /// As received, for a UAS reading the request (RFC 3261 section 12.1.1).
    AsReceived,
    /// Reversed, for a UAC reading the response (RFC 3261 section 12.1.2).
    Reversed,
}

/// Why a route set could not be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InvalidRouteSet {
    /// A Record-Route value is not a list of `name-addr` with SIP or SIPS
    /// URIs.
    Malformed,
    /// It has more URIs than the limit.
    TooLong,
}

impl RouteSet {
    /// Reads the route set from every Record-Route row, in row order.
    ///
    /// The number of URIs is bounded by `limit`, so that a peer cannot make
    /// a dialog hold an arbitrary number of them.
    pub(crate) fn from_record_route(
        headers: &HeaderMap,
        order: Order,
        limit: usize,
    ) -> Result<RouteSet, InvalidRouteSet> {
        let mut routes = Vec::new();

        for value in headers.get_all(RECORD_ROUTE) {
            for address in addresses(value.as_str()) {
                let address =
                    address.map_err(|_| InvalidRouteSet::Malformed)?;
                // `rec-route = name-addr *( SEMI rr-param )` (RFC 3261
                // section 25.1), so a bare `addr-spec` does not belong here.
                if !address.bracketed {
                    return Err(InvalidRouteSet::Malformed);
                }
                let uri = SipUri::parse(address.uri)
                    .map_err(|_| InvalidRouteSet::Malformed)?;
                let loose = uri
                    .parameter("lr")
                    .map_err(|_| InvalidRouteSet::Malformed)?
                    .is_some();

                if routes.len() == limit {
                    return Err(InvalidRouteSet::TooLong);
                }
                routes.push(Route { uri: address.uri.into(), loose });
            }
        }

        if order == Order::Reversed {
            routes.reverse();
        }
        Ok(RouteSet(routes.into()))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Route> {
        self.0.iter()
    }
}

/// The URI requests in a dialog are addressed to.
///
/// The revision changes with each refresh. A destination resolved for an
/// earlier revision is stale and must not be used for the new target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RemoteTarget {
    uri: Box<str>,
    revision: u32,
}

/// The URI is not a SIP or SIPS URI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NotSip;

impl RemoteTarget {
    /// Takes the Contact URI that forms a dialog. RFC 3261 sections 8.1.1.8
    /// and 12.1.1 require a SIP or SIPS URI there.
    pub(crate) fn new(uri: &str) -> Result<RemoteTarget, NotSip> {
        SipUri::parse(uri).map_err(|_| NotSip)?;
        Ok(RemoteTarget { uri: uri.into(), revision: 0 })
    }

    pub(crate) fn uri(&self) -> &str {
        &self.uri
    }

    /// Replaces the target, as a target refresh does (RFC 3261 section
    /// 12.2). The route set is not touched. On a URI that is not SIP or
    /// SIPS, the old target stays.
    pub(crate) fn refresh(&mut self, uri: &str) -> Result<(), NotSip> {
        SipUri::parse(uri).map_err(|_| NotSip)?;

        self.uri = uri.into();
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }
}

/// The Request-URI and Route values of a request in a dialog, and where it
/// goes first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestTarget {
    pub(crate) request_uri: String,
    /// The Route values in order, each a URI to put in angle brackets.
    pub(crate) route: Vec<Box<str>>,
    /// The URI to resolve for the first hop.
    pub(crate) next_hop: Box<str>,
    /// Whether the first hop must be secured, because the Request-URI or the
    /// next hop is a SIPS URI.
    pub(crate) secure: bool,
    /// The revision of the remote target this was built from.
    pub(crate) revision: u32,
}

/// Builds the Request-URI and Route values from the route set and remote
/// target, following RFC 3261 section 12.2.1.1.
///
/// * With an empty route set, the remote target is the Request-URI and there
///   is no Route.
/// * When the first route is a loose router, the remote target is still the
///   Request-URI, and the whole route set is the Route.
/// * When the first route is a strict router, it becomes the Request-URI.
///   The rest of the route set follows in Route, and the remote target goes
///   last, so that a loose router later on can put it back.
///
/// A URI moved into the Request-URI loses what Table 1 of RFC 3261 section
/// 19.1.1 does not allow there, which is the `method` parameter and the
/// headers. Section 12.2.1.1 says so for a strict router. For the remote
/// target, I follow the table's advice to ignore disallowed components.
pub(crate) fn request_target(
    routes: &RouteSet,
    target: &RemoteTarget,
    secure_dialog: bool,
) -> RequestTarget {
    let (request_uri, route, next_hop) = match routes.0.split_first() {
        None => {
            let request_uri = request_uri(target.uri());
            let next_hop = request_uri.as_str().into();
            (request_uri, Vec::new(), next_hop)
        }
        Some((first, _)) if first.loose => {
            let route =
                routes.0.iter().map(|route| route.uri.clone()).collect();
            (request_uri(target.uri()), route, first.uri.clone())
        }
        Some((first, rest)) => {
            let mut route: Vec<Box<str>> =
                rest.iter().map(|route| route.uri.clone()).collect();
            route.push(target.uri.clone());
            let request_uri = request_uri(&first.uri);
            // RFC 3261 section 8.1.2 resolves the Request-URI when the first
            // route is a strict router.
            let next_hop = request_uri.as_str().into();
            (request_uri, route, next_hop)
        }
    };

    // RFC 3261 section 8.1.2 has the UAC treat the next hop as SIPS whenever
    // the Request-URI is a SIPS URI, whatever URI it resolves.
    let secure = secure_dialog || is_sips(&request_uri) || is_sips(&next_hop);
    RequestTarget {
        request_uri,
        route,
        next_hop,
        secure,
        revision: target.revision,
    }
}

fn is_sips(uri: &str) -> bool {
    SipUri::parse(uri).is_ok_and(|uri| uri.scheme() == Scheme::Sips)
}

/// Copies a SIP or SIPS URI without its `method` parameter and headers.
fn request_uri(src: &str) -> String {
    let Ok(uri) = SipUri::parse(src) else {
        // Route set and target URIs were checked when stored.
        return src.into();
    };

    let mut out = String::with_capacity(src.len());
    out.push_str(&src[..address_end(&uri)]);
    for parameter in uri.parameters() {
        if parameter.name().as_str().eq_ignore_ascii_case("method") {
            continue;
        }
        out.push(';');
        out.push_str(parameter.name().as_str());
        if let Some(value) = parameter.value() {
            out.push('=');
            out.push_str(value.as_str());
        }
    }
    out
}

/// Returns where the host and port of `uri` end, which is where its
/// parameters or headers start.
fn address_end(uri: &SipUri<'_>) -> usize {
    let src = uri.as_str();
    let offset = |part: &str| part.as_ptr() as usize - src.as_ptr() as usize;

    match uri.port() {
        Some(port) => offset(port) + port.len(),
        None => {
            let host = uri.host();
            let end = offset(host) + host.len();
            // An IPv6 reference comes without its brackets.
            if src[end..].starts_with(']') { end + 1 } else { end }
        }
    }
}

/// Returns the URI to resolve for a request outside a dialog, and whether
/// its first hop must be secured.
///
/// RFC 3261 section 8.1.2 resolves the top Route value, or the Request-URI
/// without one. When the top Route value is a strict router, the request was
/// built as section 12.2.1.1 builds it, and the Request-URI is resolved. A
/// SIPS Request-URI makes the hop secure whatever is resolved.
pub(crate) fn initial_next_hop(
    request_uri: &str,
    headers: &HeaderMap,
) -> Result<(Box<str>, bool), Malformed> {
    let malformed = Malformed(Field::Route);
    let top = match headers.get(ROUTE) {
        Some(value) => addresses(value.as_str())
            .next()
            .transpose()
            .map_err(|_| malformed)?,
        None => None,
    };

    let next_hop = match top {
        // `route-param = name-addr *( SEMI rr-param )` (RFC 3261 section
        // 25.1), so a bare `addr-spec` does not belong here either.
        Some(route) if !route.bracketed => return Err(malformed),
        Some(route) => {
            let uri = SipUri::parse(route.uri).map_err(|_| malformed)?;
            let loose = uri.parameter("lr").map_err(|_| malformed)?.is_some();
            if loose { route.uri } else { request_uri }
        }
        None => request_uri,
    };
    let secure = is_sips(request_uri) || is_sips(next_hop);
    Ok((next_hop.into(), secure))
}

/// Where the first hop of a request goes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NextHop {
    pub(crate) transport: Transport,
    pub(crate) address: SocketAddr,
}

/// Why a next hop did not resolve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
pub enum ResolveError {
    /// The hop must be secured, and there is no TLS to secure it with.
    SecureTransportUnavailable,
    /// The host is a name without an entry in the table.
    Unresolved,
    /// The URI asks for a transport other than UDP or TCP.
    UnsupportedTransport,
    /// The URI is not a SIP or SIPS URI, or its port does not fit.
    InvalidUri,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ResolveError::SecureTransportUnavailable => {
                "the hop must be secured, and there is no TLS"
            }
            ResolveError::Unresolved => "the host has no known address",
            ResolveError::UnsupportedTransport => {
                "the URI asks for a transport other than UDP or TCP"
            }
            ResolveError::InvalidUri => "the URI cannot be resolved",
        })
    }
}

impl error::Error for ResolveError {}

/// Resolves next-hop URIs from IP literals and a fixed table of host names.
///
/// It does no DNS, so it is not an RFC 3263 resolver. RFC 3261 section 8.1.2
/// lets local policy pick the destination, and the table is that policy. A
/// host name without an entry does not resolve.
///
/// * The `maddr` parameter stands for the host, as RFC 3263 section 4 has
///   it.
/// * The `transport` parameter picks UDP or TCP, and UDP is the default for
///   a SIP URI (RFC 3263 section 4.1). Any other transport does not resolve.
/// * The port is the URI's, or 5060.
/// * A request over 1300 bytes goes over TCP even where UDP was picked, as
///   RFC 3261 section 18.1.1 requires.
///
/// It never resolves a SIPS URI, since there is no TLS. RFC 3261 section
/// 26.2.2 requires TLS on every hop toward one, and RFC 5630 section 5.1.1
/// forbids a UAC to turn it into a SIP URI.
#[derive(Clone, Debug, Default)]
#[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
pub struct StaticResolver {
    hosts: HashMap<Box<str>, IpAddr>,
}

/// Above this, a request does not go over UDP (RFC 3261 section 18.1.1).
const UDP_LIMIT: usize = 1300;

/// The port of a SIP URI over UDP or TCP that names none (RFC 3261 section
/// 19.1.1, Table 1).
const DEFAULT_PORT: u16 = 5060;

impl StaticResolver {
    /// Creates a resolver with an empty table, which resolves IP literals
    /// only.
    #[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
    pub fn new() -> StaticResolver {
        StaticResolver::default()
    }

    /// Maps a host name to an address. Host names compare without regard
    /// to ASCII case or a trailing dot, as DNS names do.
    #[cfg_attr(not(feature = "tokio"), allow(unreachable_pub))]
    pub fn insert(&mut self, host: &str, address: IpAddr) {
        self.hosts.insert(host_key(host).into(), address);
    }

    /// Resolves the next hop of a request of `size` bytes.
    pub(crate) fn resolve(
        &self,
        target: &RequestTarget,
        size: usize,
    ) -> Result<NextHop, ResolveError> {
        if target.secure {
            return Err(ResolveError::SecureTransportUnavailable);
        }
        self.resolve_uri(&target.next_hop, size)
    }

    /// Resolves a next-hop URI for a request of `size` bytes.
    pub(crate) fn resolve_uri(
        &self,
        uri: &str,
        size: usize,
    ) -> Result<NextHop, ResolveError> {
        let uri = SipUri::parse(uri).map_err(|_| ResolveError::InvalidUri)?;
        if uri.scheme() == Scheme::Sips {
            return Err(ResolveError::SecureTransportUnavailable);
        }

        // RFC 3263 section 4 resolves `maddr` in place of the host when the
        // URI has one.
        let maddr = uri
            .parameter("maddr")
            .map_err(|_| ResolveError::InvalidUri)?
            .and_then(|maddr| maddr.value());
        let host = match maddr {
            Some(maddr) => {
                maddr.as_str().trim_start_matches('[').trim_end_matches(']')
            }
            None => uri.host(),
        };

        // RFC 3263 section 4.1 takes the `transport` parameter, and UDP for
        // a SIP URI without one. RFC 3261 section 18.1.1 moves a request
        // over 1300 bytes to a congestion-controlled transport.
        let transport = uri
            .parameter("transport")
            .map_err(|_| ResolveError::InvalidUri)?
            .and_then(|transport| transport.value());
        let transport = match transport.map(|transport| transport.as_str()) {
            None => Transport::Udp,
            Some(name) if name.eq_ignore_ascii_case("udp") => Transport::Udp,
            Some(name) if name.eq_ignore_ascii_case("tcp") => Transport::Tcp,
            Some(_) => return Err(ResolveError::UnsupportedTransport),
        };
        let transport = if transport == Transport::Udp && size > UDP_LIMIT {
            Transport::Tcp
        } else {
            transport
        };

        let port = uri
            .port_u16()
            .map_err(|_| ResolveError::InvalidUri)?
            .unwrap_or(DEFAULT_PORT);
        let ip = match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => *self
                .hosts
                .get(host_key(host).as_str())
                .ok_or(ResolveError::Unresolved)?,
        };

        Ok(NextHop { transport, address: SocketAddr::new(ip, port) })
    }
}

fn host_key(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use signa_core::HeaderValue;

    use super::*;

    fn record_route(values: &[&'static str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(RECORD_ROUTE, HeaderValue::from_static(value));
        }
        headers
    }

    fn routes(values: &[&'static str]) -> RouteSet {
        RouteSet::from_record_route(
            &record_route(values),
            Order::AsReceived,
            8,
        )
        .unwrap()
    }

    fn uris(routes: &RouteSet) -> Vec<&str> {
        routes.iter().map(Route::uri).collect()
    }

    fn target(uri: &str) -> RemoteTarget {
        RemoteTarget::new(uri).unwrap()
    }

    #[test]
    fn rows_and_lists_both_add_routes() {
        let routes = routes(&[
            "<sip:p1.example.com;lr>, <sip:p2.example.com;lr>",
            "<sip:p3.example.com>",
        ]);

        assert_eq!(
            uris(&routes),
            [
                "sip:p1.example.com;lr",
                "sip:p2.example.com;lr",
                "sip:p3.example.com"
            ],
        );
    }

    #[test]
    fn route_sets_are_bounded() {
        let headers = record_route(&["<sip:p1;lr>, <sip:p2;lr>, <sip:p3;lr>"]);

        assert_eq!(
            RouteSet::from_record_route(&headers, Order::AsReceived, 2),
            Err(InvalidRouteSet::TooLong),
        );
        assert!(
            RouteSet::from_record_route(&headers, Order::AsReceived, 3)
                .is_ok()
        );
    }

    #[test]
    fn record_route_needs_bracketed_sip_uris() {
        for value in
            ["sip:p1.example.com;lr", "<tel:+15551234>", "<sip:p1;lr;lr>"]
        {
            let headers = record_route(&[value]);
            assert_eq!(
                RouteSet::from_record_route(&headers, Order::AsReceived, 8),
                Err(InvalidRouteSet::Malformed),
                "{value}",
            );
        }
    }

    #[test]
    fn an_empty_route_set_sends_to_the_remote_target() {
        let request = request_target(
            &RouteSet::default(),
            &target("sip:bob@192.0.2.4"),
            false,
        );

        assert_eq!(request.request_uri, "sip:bob@192.0.2.4");
        assert!(request.route.is_empty());
        assert_eq!(&*request.next_hop, "sip:bob@192.0.2.4");
    }

    #[test]
    fn loose_router_keeps_remote_target_as_request_uri() {
        let routes =
            routes(&["<sip:p1.example.com;lr>", "<sip:p2.example.com;lr>"]);

        let request =
            request_target(&routes, &target("sip:bob@192.0.2.4"), false);

        assert_eq!(request.request_uri, "sip:bob@192.0.2.4");
        assert_eq!(
            request.route,
            ["sip:p1.example.com;lr".into(), "sip:p2.example.com;lr".into()]
                as [Box<str>; 2],
        );
        assert_eq!(&*request.next_hop, "sip:p1.example.com;lr");
    }

    /// The example of RFC 3261 section 12.2.1.1.
    #[test]
    fn strict_router_moves_remote_target_to_route_tail() {
        let routes = routes(&[
            "<sip:proxy1>,<sip:proxy2>,<sip:proxy3;lr>,<sip:proxy4>",
        ]);

        let request =
            request_target(&routes, &target("sip:user@remoteua"), false);

        assert_eq!(request.request_uri, "sip:proxy1");
        assert_eq!(
            request.route,
            [
                "sip:proxy2".into(),
                "sip:proxy3;lr".into(),
                "sip:proxy4".into(),
                "sip:user@remoteua".into(),
            ] as [Box<str>; 4],
        );
        assert_eq!(&*request.next_hop, "sip:proxy1");
    }

    #[test]
    fn the_request_uri_drops_what_it_does_not_allow() {
        let routes = routes(&[
            "<sip:proxy1:5070;method=INVITE;transport=tcp?Subject=x>",
        ]);

        let request = request_target(
            &routes,
            &target("sip:user@[2001:db8::1];method=BYE"),
            false,
        );

        assert_eq!(request.request_uri, "sip:proxy1:5070;transport=tcp");
        assert_eq!(
            request.route.last().map(|uri| &**uri),
            Some("sip:user@[2001:db8::1];method=BYE"),
        );
        let direct = request_target(
            &RouteSet::default(),
            &target("sip:[2001:db8::1];method=BYE"),
            false,
        );
        assert_eq!(direct.request_uri, "sip:[2001:db8::1]");
    }

    #[test]
    fn target_refresh_keeps_the_route_set() {
        let routes = routes(&["<sip:p1.example.com;lr>"]);
        let mut target = target("sip:bob@192.0.2.4");

        target.refresh("sip:bob@192.0.2.5").unwrap();
        assert!(target.refresh("tel:+15551234").is_err());

        let request = request_target(&routes, &target, false);
        assert_eq!(request.request_uri, "sip:bob@192.0.2.5");
        assert_eq!(&*request.next_hop, "sip:p1.example.com;lr");
        assert_eq!(request.revision, 1);
    }

    #[test]
    fn sips_requirement_never_falls_back_to_plaintext() {
        let mut resolver = StaticResolver::new();
        resolver.insert("p1.example.com", "192.0.2.10".parse().unwrap());

        for (routes, target, secure_dialog) in [
            (RouteSet::default(), "sips:bob@192.0.2.4", false),
            (
                routes(&["<sips:p1.example.com;lr>"]),
                "sip:bob@192.0.2.4",
                false,
            ),
            (
                routes(&["<sip:p1.example.com;lr>"]),
                "sips:bob@192.0.2.4",
                false,
            ),
            (routes(&["<sip:p1.example.com;lr>"]), "sip:bob@192.0.2.4", true),
        ] {
            let request =
                request_target(&routes, &self::target(target), secure_dialog);

            assert!(request.secure, "{target}");
            assert_eq!(
                resolver.resolve(&request, 100),
                Err(ResolveError::SecureTransportUnavailable),
                "{target}",
            );
        }
    }

    #[test]
    fn literals_resolve_with_their_transport_and_port() {
        let resolver = StaticResolver::new();
        let resolve = |uri: &str, size| {
            let request =
                request_target(&RouteSet::default(), &target(uri), false);
            resolver.resolve(&request, size)
        };

        assert_eq!(
            resolve("sip:bob@192.0.2.4", 100),
            Ok(NextHop {
                transport: Transport::Udp,
                address: "192.0.2.4:5060".parse().unwrap()
            }),
        );
        assert_eq!(
            resolve("sip:bob@[2001:db8::1]:5070;transport=TCP", 100),
            Ok(NextHop {
                transport: Transport::Tcp,
                address: "[2001:db8::1]:5070".parse().unwrap()
            }),
        );
        assert_eq!(
            resolve("sip:bob@example.com;maddr=192.0.2.9", 100),
            Ok(NextHop {
                transport: Transport::Udp,
                address: "192.0.2.9:5060".parse().unwrap()
            }),
        );
        assert_eq!(
            resolve("sip:bob@192.0.2.4;transport=sctp", 100),
            Err(ResolveError::UnsupportedTransport)
        );
        assert_eq!(
            resolve("sip:bob@192.0.2.4:70000", 100),
            Err(ResolveError::InvalidUri)
        );
    }

    #[test]
    fn a_large_request_leaves_udp() {
        let resolver = StaticResolver::new();
        let request = request_target(
            &RouteSet::default(),
            &target("sip:bob@192.0.2.4;transport=udp"),
            false,
        );

        assert_eq!(
            resolver.resolve(&request, UDP_LIMIT).unwrap().transport,
            Transport::Udp
        );
        assert_eq!(
            resolver.resolve(&request, UDP_LIMIT + 1).unwrap().transport,
            Transport::Tcp
        );
    }

    #[test]
    fn an_unmapped_hostname_is_not_resolved() {
        let mut resolver = StaticResolver::new();
        let request = request_target(
            &RouteSet::default(),
            &target("sip:bob@Biloxi.Example.COM."),
            false,
        );

        assert_eq!(
            resolver.resolve(&request, 100),
            Err(ResolveError::Unresolved)
        );

        resolver.insert("biloxi.example.com", "192.0.2.4".parse().unwrap());
        assert_eq!(
            resolver.resolve(&request, 100).unwrap().address,
            "192.0.2.4:5060".parse().unwrap()
        );
    }

    /// RFC 3261 section 8.1.2 sends a request outside a dialog to its top
    /// Route, or to its Request-URI without one or past a strict router.
    #[test]
    fn the_first_hop_of_an_initial_request() {
        let route = |value: &'static str| {
            let mut headers = HeaderMap::new();
            headers.append(ROUTE, HeaderValue::from_static(value));
            headers
        };
        let uri = "sip:bob@192.0.2.4";

        assert_eq!(
            initial_next_hop(uri, &HeaderMap::new()),
            Ok((uri.into(), false)),
        );
        assert_eq!(
            initial_next_hop(uri, &route("<sip:p1.example.com;lr>, <sip:p2>")),
            Ok(("sip:p1.example.com;lr".into(), false)),
        );
        assert_eq!(
            initial_next_hop(uri, &route("<sip:p1.example.com>")),
            Ok((uri.into(), false)),
        );
        assert_eq!(
            initial_next_hop(uri, &route("<sips:p1.example.com;lr>")),
            Ok(("sips:p1.example.com;lr".into(), true)),
        );
        assert_eq!(
            initial_next_hop("sips:bob@192.0.2.4", &HeaderMap::new()),
            Ok(("sips:bob@192.0.2.4".into(), true)),
        );
        for malformed in ["sip:p1.example.com;lr", "<tel:+15551234>"] {
            assert_eq!(
                initial_next_hop(uri, &route(malformed)),
                Err(Malformed(Field::Route)),
                "{malformed}",
            );
        }
    }
}
