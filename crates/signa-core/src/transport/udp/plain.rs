/*!
Plain `recv_from` and `send_to` for the platforms without `PKTINFO`
support in signa, Windows among them.

The destination address of a datagram is not reported, so a socket bound
to a wildcard address answers from whatever source the kernel picks.
*/

use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use bytes::BytesMut;
use tokio::net::UdpSocket;

use super::Received;

pub(super) fn configure(
    _socket: &std::net::UdpSocket,
    _ipv4: bool,
) -> io::Result<()> {
    Ok(())
}

pub(super) fn recv(
    socket: &UdpSocket,
    buf: &mut BytesMut,
) -> io::Result<Received> {
    let (len, remote) = socket.try_recv_buf_from(buf)?;
    Ok(Received { len, remote, local: None })
}

/// Whether `send` sends from the source it is given. Here the kernel picks.
pub(super) const NAMES_SOURCE: bool = false;

pub(super) fn send(
    socket: &UdpSocket,
    data: &[u8],
    remote: SocketAddr,
    _source: Option<IpAddr>,
) -> io::Result<usize> {
    socket.try_send_to(data, remote)
}
