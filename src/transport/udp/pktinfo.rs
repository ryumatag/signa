/*!
`recvmsg` and `sendmsg` with the `PKTINFO` control messages.

Written against Linux, Android, and Darwin, which agree on the socket options,
the control message types, and the `in_pktinfo` and `in6_pktinfo` layouts used
here. Darwin's `IP_RECVPKTINFO` is the same value as its `IP_PKTINFO`, which is
why the latter enables the option on both. The handling follows quinn-udp's.
*/

use std::{
    io,
    mem::{self, MaybeUninit},
    net::{
        IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
    },
    os::fd::AsRawFd,
    ptr,
};

use bytes::{BufMut, BytesMut};
use libc::{c_int, c_void, socklen_t};
use tokio::net::UdpSocket;

use super::Received;

/// Room for the control messages one call carries. The largest is one
/// `in6_pktinfo` with its header and padding, which `CMSG_SPACE` puts at 32
/// bytes on these platforms. The alignment is what `cmsghdr` needs.
#[repr(C, align(8))]
struct Control([u8; 64]);

impl Control {
    const LEN: usize = 64;

    fn new() -> Control {
        Control([0; Control::LEN])
    }
}

/// Asks the kernel to report the destination address of each datagram.
pub(super) fn configure(
    socket: &std::net::UdpSocket,
    ipv4: bool,
) -> io::Result<()> {
    if ipv4 {
        set_option(socket, libc::IPPROTO_IP, libc::IP_PKTINFO)
    } else {
        set_option(socket, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    }
}

fn set_option(
    socket: &impl AsRawFd,
    level: c_int,
    name: c_int,
) -> io::Result<()> {
    let value: c_int = 1;
    // SAFETY: `value` lives for the call, and the length passed is its size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            ptr::addr_of!(value).cast::<c_void>(),
            mem::size_of::<c_int>() as socklen_t,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Receives one datagram into the spare capacity of `buf` and advances it.
///
/// The caller has reserved room for the largest datagram, so nothing is
/// truncated.
pub(super) fn recv(
    socket: &UdpSocket,
    buf: &mut BytesMut,
) -> io::Result<Received> {
    let mut name = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut control = Control::new();
    let spare = buf.spare_capacity_mut();
    let mut iov = libc::iovec {
        iov_base: spare.as_mut_ptr().cast::<c_void>(),
        iov_len: spare.len(),
    };
    // SAFETY: `msghdr` is plain data, and all zeros is a valid value.
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
    hdr.msg_name = name.as_mut_ptr().cast::<c_void>();
    hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as socklen_t;
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = control.0.as_mut_ptr().cast::<c_void>();
    hdr.msg_controllen = Control::LEN as _;

    // SAFETY: Every pointer in `hdr` is to a live buffer of the length given
    // next to it, and they all outlive the call.
    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut hdr, 0) };
    if n == -1 {
        return Err(io::Error::last_os_error());
    }
    let len = n as usize;
    // SAFETY: The kernel wrote `len` bytes at the start of the spare capacity,
    // which `iov` pointed at.
    unsafe { buf.advance_mut(len) };

    // SAFETY: The kernel filled in the name, and the storage was zeroed before
    // the call, so every byte of it is initialized.
    let name = unsafe { name.assume_init() };
    let remote = socket_addr(&name, hdr.msg_namelen)?;
    let local = destination(&hdr);

    Ok(Received { len, remote, local })
}

/// Finds the destination address among the control messages of a receive.
fn destination(hdr: &libc::msghdr) -> Option<IpAddr> {
    // SAFETY: `hdr` describes the control buffer the kernel just filled, with
    // `msg_controllen` set to what it wrote, and the macros stay within that
    // length.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(hdr) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` points at a header inside the control buffer.
        let (len, level, ty) = unsafe {
            ((*cmsg).cmsg_len as usize, (*cmsg).cmsg_level, (*cmsg).cmsg_type)
        };

        // A header shorter than itself is the end of the chain, not a message.
        // Some Darwin versions have returned one instead of null.
        if len < mem::size_of::<libc::cmsghdr>() {
            return None;
        }

        match (level, ty) {
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                // SAFETY: The kernel put an `in_pktinfo` in this message. The
                // data is only aligned for `cmsghdr`, hence the unaligned
                // read.
                let info: libc::in_pktinfo = unsafe {
                    ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast())
                };
                let octets = info.ipi_addr.s_addr.to_ne_bytes();

                return Some(IpAddr::V4(Ipv4Addr::from(octets)));
            }
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                // SAFETY: As above, with an `in6_pktinfo`.
                let info: libc::in6_pktinfo = unsafe {
                    ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast())
                };
                let ip = Ipv6Addr::from(info.ipi6_addr.s6_addr);

                return Some(IpAddr::V6(ip));
            }
            _ => {}
        }

        // SAFETY: `cmsg` is a header the kernel wrote within the buffer that
        // `hdr` describes.
        cmsg = unsafe { libc::CMSG_NXTHDR(hdr, cmsg) };
    }

    None
}

/// Sends `data` to `remote`, from `source` when one is given.
pub(super) fn send(
    socket: &UdpSocket,
    data: &[u8],
    remote: SocketAddr,
    source: Option<IpAddr>,
) -> io::Result<usize> {
    let (name, name_len) = raw_addr(remote);
    let mut iov = libc::iovec {
        // `sendmsg` reads through this pointer. The type is mutable only
        // because `recvmsg` shares it.
        iov_base: data.as_ptr().cast_mut().cast::<c_void>(),
        iov_len: data.len(),
    };
    let mut control = Control::new();
    // SAFETY: As in `recv`.
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
    hdr.msg_name = ptr::addr_of!(name).cast_mut().cast::<c_void>();
    hdr.msg_namelen = name_len;
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;

    if let Some(source) = source {
        hdr.msg_control = control.0.as_mut_ptr().cast::<c_void>();
        hdr.msg_controllen = Control::LEN as _;
        // SAFETY: `hdr` names the control buffer with its full length, so the
        // first header fits, and `write_cmsg` checks that the payload does
        // too.
        let used = unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&hdr);
            match source {
                IpAddr::V4(ip) => {
                    let addr = libc::in_addr {
                        s_addr: u32::from_ne_bytes(ip.octets()),
                    };
                    // `ipi_spec_dst` names the source. `ipi_addr` is the
                    // destination in the header, which the kernel sets.
                    let info = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: addr,
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };

                    write_cmsg(cmsg, libc::IPPROTO_IP, libc::IP_PKTINFO, info)
                }
                IpAddr::V6(ip) => {
                    let info = libc::in6_pktinfo {
                        ipi6_ifindex: 0,
                        ipi6_addr: libc::in6_addr { s6_addr: ip.octets() },
                    };

                    write_cmsg(
                        cmsg,
                        libc::IPPROTO_IPV6,
                        libc::IPV6_PKTINFO,
                        info,
                    )
                }
            }
        };

        hdr.msg_controllen = used as _;
    }

    // SAFETY: Every pointer in `hdr` is to a live buffer of the length given
    // next to it, and they all outlive the call.
    let n = unsafe { libc::sendmsg(socket.as_raw_fd(), &hdr, 0) };
    if n == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(n as usize)
}

/// Writes one control message at `cmsg` and returns the space it takes.
///
/// # Safety
///
/// `cmsg` must point into a control buffer with `CMSG_SPACE` of `T` bytes
/// left from there.
unsafe fn write_cmsg<T: Copy>(
    cmsg: *mut libc::cmsghdr,
    level: c_int,
    ty: c_int,
    value: T,
) -> usize {
    let size = mem::size_of::<T>() as u32;
    let space = libc::CMSG_SPACE(size) as usize;

    assert!(space <= Control::LEN, "control message does not fit");

    (*cmsg).cmsg_level = level;
    (*cmsg).cmsg_type = ty;
    (*cmsg).cmsg_len = libc::CMSG_LEN(size) as _;

    // The data is only aligned for `cmsghdr`.
    ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<T>(), value);

    space
}

/// Builds the `sockaddr` for `addr` in a storage big enough for either family,
/// with the length to pass alongside it.
fn raw_addr(addr: SocketAddr) -> (libc::sockaddr_storage, socklen_t) {
    // SAFETY: The socket address structures are plain data, and all zeros is a
    // valid value of each. The fields set below are the ones the kernel reads.
    // Darwin's `sin_len` can stay zero, as it does in std.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(addr) => {
            // SAFETY: As above.
            let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
            sin.sin_family = libc::AF_INET as _;
            sin.sin_port = addr.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            };
            // SAFETY: `sockaddr_in` fits in `sockaddr_storage`, which is
            // aligned for every socket address.
            unsafe {
                ptr::addr_of_mut!(storage)
                    .cast::<libc::sockaddr_in>()
                    .write(sin)
            };

            mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(addr) => {
            // SAFETY: As above.
            let mut sin6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
            sin6.sin6_family = libc::AF_INET6 as _;
            sin6.sin6_port = addr.port().to_be();
            sin6.sin6_flowinfo = addr.flowinfo();
            sin6.sin6_addr = libc::in6_addr { s6_addr: addr.ip().octets() };
            sin6.sin6_scope_id = addr.scope_id();
            // SAFETY: As above, with `sockaddr_in6`.
            unsafe {
                ptr::addr_of_mut!(storage)
                    .cast::<libc::sockaddr_in6>()
                    .write(sin6)
            };

            mem::size_of::<libc::sockaddr_in6>()
        }
    };

    (storage, len as socklen_t)
}

/// Reads the address the kernel put in `storage`.
fn socket_addr(
    storage: &libc::sockaddr_storage,
    len: socklen_t,
) -> io::Result<SocketAddr> {
    let len = len as usize;
    match c_int::from(storage.ss_family) {
        libc::AF_INET if len >= mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: The family says the storage holds a `sockaddr_in`,
            // and the length check says the kernel wrote all of it.
            let sin: libc::sockaddr_in = unsafe {
                ptr::addr_of!(*storage).cast::<libc::sockaddr_in>().read()
            };
            let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            let port = u16::from_be(sin.sin_port);

            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 if len >= mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: As above, with `sockaddr_in6`.
            let sin6: libc::sockaddr_in6 = unsafe {
                ptr::addr_of!(*storage).cast::<libc::sockaddr_in6>().read()
            };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);

            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected address family on a UDP socket",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_round_trip_through_the_raw_form() {
        let v4 = "192.0.2.1:5060".parse::<SocketAddr>().unwrap();
        let v6 = "[2001:db8::1%7]:5061".parse::<SocketAddr>().unwrap();
        for addr in [v4, v6] {
            let (storage, len) = raw_addr(addr);
            assert_eq!(socket_addr(&storage, len).unwrap(), addr);
        }
    }

    #[test]
    fn a_short_or_foreign_address_is_an_error() {
        let (storage, len) = raw_addr("192.0.2.1:5060".parse().unwrap());
        assert!(socket_addr(&storage, len - 1).is_err());
        // SAFETY: All zeros is a valid `sockaddr_storage`.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        storage.ss_family = libc::AF_UNIX as _;
        assert!(socket_addr(&storage, len).is_err());
    }
}
