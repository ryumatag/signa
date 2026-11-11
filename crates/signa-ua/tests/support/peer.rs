/*!
Raw peers on loopback, over UDP and TCP, that play the other side of a UA.
*/

use std::{net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

use crate::support::{
    LOADED, WAIT,
    message::{ack_for, header},
};

/// A UDP socket that plays the other side.
pub(crate) struct Peer {
    socket: UdpSocket,
}

impl Peer {
    pub(crate) async fn new() -> Peer {
        Peer { socket: UdpSocket::bind("127.0.0.1:0").await.unwrap() }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    /// Sends `message`, with each line ending in CRLF whether it was
    /// written with bare line feeds or not.
    pub(crate) async fn send(&self, message: &str, to: SocketAddr) {
        let message = message.replace("\r\n", "\n").replace('\n', "\r\n");
        self.socket.send_to(message.as_bytes(), to).await.unwrap();
    }

    /// Receives the next datagram as text, and where it came from.
    pub(crate) async fn recv(&self) -> (String, SocketAddr) {
        let mut buffer = vec![0; 65_536];
        let (n, from) = timeout(WAIT, self.socket.recv_from(&mut buffer))
            .await
            .expect("a datagram in time")
            .unwrap();
        (String::from_utf8(buffer[..n].to_vec()).unwrap(), from)
    }

    /// Receives datagrams until one starts with `start`, skipping the rest,
    /// such as a 100 Trying.
    pub(crate) async fn recv_starting(
        &self,
        start: &str,
    ) -> (String, SocketAddr) {
        loop {
            let (message, from) = self.recv().await;
            if message.starts_with(start) {
                return (message, from);
            }
        }
    }

    /// Checks that nothing starting with `start` arrives for a while.
    pub(crate) async fn quiet(&self, start: &str, wait: Duration) {
        let _ = timeout(wait, async {
            loop {
                let (message, _) = self.recv().await;
                assert!(!message.starts_with(start), "unexpected {message}");
            }
        })
        .await;
    }

    /// Checks that each failure response arriving for a while answers the
    /// request on `branch`.
    pub(crate) async fn only_failures_for(
        &self,
        branch: &str,
        wait: Duration,
    ) {
        let _ = timeout(wait, async {
            loop {
                let (message, _) = self.recv().await;
                if message.starts_with("SIP/2.0 4") {
                    let via = header(&message, "Via");
                    assert!(via[0].contains(branch), "unexpected {message}");
                }
            }
        })
        .await;
    }

    /// Reads and discards what arrives for a while, such as a copy already
    /// on its way.
    pub(crate) async fn drain(&self, wait: Duration) {
        let _ = timeout(wait, async {
            loop {
                self.recv().await;
            }
        })
        .await;
    }

    /// Receives datagrams for up to `wait` until one starts with `start`.
    pub(crate) async fn recv_starting_within(
        &self,
        start: &str,
        wait: Duration,
    ) -> (String, SocketAddr) {
        let next = async {
            let mut buffer = vec![0; 65_536];
            loop {
                let (n, from) =
                    self.socket.recv_from(&mut buffer).await.unwrap();
                let message = String::from_utf8(buffer[..n].to_vec()).unwrap();
                if message.starts_with(start) {
                    return (message, from);
                }
            }
        };
        timeout(wait, next).await.expect("a datagram in time")
    }
}

/// A TCP connection that plays the other side.
pub(crate) struct TcpPeer {
    pub(crate) stream: TcpStream,
    pub(crate) buffer: Vec<u8>,
}

impl TcpPeer {
    pub(crate) async fn connect(to: SocketAddr) -> TcpPeer {
        TcpPeer {
            stream: TcpStream::connect(to).await.unwrap(),
            buffer: Vec::new(),
        }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.stream.local_addr().unwrap()
    }

    pub(crate) async fn send(&mut self, message: &str) {
        let message = message.replace("\r\n", "\n").replace('\n', "\r\n");
        self.stream.write_all(message.as_bytes()).await.unwrap();
    }

    /// Receives the next message off the stream, framed by its
    /// Content-Length.
    pub(crate) async fn recv(&mut self) -> String {
        let read = async {
            loop {
                if let Some(message) = self.framed() {
                    return message;
                }
                let mut chunk = [0; 4096];
                let n = self.stream.read(&mut chunk).await.unwrap();
                assert!(n > 0, "the UA closed the connection");
                self.buffer.extend_from_slice(&chunk[..n]);
            }
        };
        timeout(WAIT, read).await.expect("a message in time")
    }

    /// Takes the first whole message out of the buffer.
    fn framed(&mut self) -> Option<String> {
        let end = self.buffer.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = std::str::from_utf8(&self.buffer[..end]).unwrap();
        let length = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| {
                name.trim().eq_ignore_ascii_case("content-length")
            })
            .map_or(0, |(_, value)| value.trim().parse().unwrap());
        let total = end + 4 + length;
        if self.buffer.len() < total {
            return None;
        }
        let message = self.buffer.drain(..total).collect();
        Some(String::from_utf8(message).unwrap())
    }

    pub(crate) async fn recv_starting(&mut self, start: &str) -> String {
        loop {
            let message = self.recv().await;
            if message.starts_with(start) {
                return message;
            }
        }
    }
}

/// A raw peer over UDP or TCP.
pub(crate) enum Wire {
    Udp { peer: Peer, to: SocketAddr },
    Tcp(TcpPeer),
}

impl Wire {
    /// Connects to the UA's address for `transport`, `UDP` or `TCP`.
    pub(crate) async fn connect(
        transport: &str,
        udp: SocketAddr,
        tcp: SocketAddr,
    ) -> Wire {
        if transport == "UDP" {
            Wire::Udp { peer: Peer::new().await, to: udp }
        } else {
            Wire::Tcp(TcpPeer::connect(tcp).await)
        }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        match self {
            Wire::Udp { peer, .. } => peer.address(),
            Wire::Tcp(peer) => peer.address(),
        }
    }

    pub(crate) async fn send(&mut self, message: &str) {
        match self {
            Wire::Udp { peer, to } => peer.send(message, *to).await,
            Wire::Tcp(peer) => peer.send(message).await,
        }
    }

    /// Receives messages until one starts with `start` and has `cseq` as
    /// its CSeq.
    pub(crate) async fn recv_answer(
        &mut self,
        start: &str,
        cseq: &str,
    ) -> String {
        loop {
            let message = match self {
                Wire::Udp { peer, .. } => peer.recv().await.0,
                Wire::Tcp(peer) => peer.recv().await,
            };
            if message.starts_with(start) && header(&message, "CSeq") == [cseq]
            {
                return message;
            }
        }
    }

    /// Sends a request and waits for the answer that starts with `start`
    /// and has `cseq` as its CSeq. Over UDP it sends the request again every
    /// 100 ms until then, as a client transaction does (RFC 3261 section
    /// 17.1.2.2), since a flood can make the UA's socket drop datagrams.
    pub(crate) async fn request(
        &mut self,
        message: &str,
        start: &str,
        cseq: &str,
    ) -> String {
        loop {
            self.send(message).await;
            let wait = match self {
                Wire::Udp { .. } => Duration::from_millis(100),
                Wire::Tcp(_) => WAIT,
            };
            if let Ok(answer) =
                timeout(wait, self.recv_answer(start, cseq)).await
            {
                return answer;
            }
        }
    }

    /// Acknowledges the 2xx `ok` to the INVITE `call` numbered `cseq`, as a
    /// UAC does: once, and again for each copy of the 2xx that still comes
    /// (RFC 3261 section 13.2.2.4). Returns how many ACKs it sent once the
    /// copies stop.
    pub(crate) async fn acknowledge(
        &mut self,
        ok: &str,
        call: &str,
        cseq: u32,
    ) -> usize {
        let transport =
            if matches!(self, Wire::Udp { .. }) { "UDP" } else { "TCP" };
        let ack = ack_for(ok, self.address(), call, cseq)
            .replace("SIP/2.0/UDP", &format!("SIP/2.0/{transport}"));
        let copy = format!("{cseq} INVITE");
        let mut sent = 0;
        loop {
            self.send(&ack).await;
            sent += 1;
            // Copies come at most T2 apart.
            let quiet = LOADED.t2() * 3;
            if timeout(quiet, self.recv_answer("SIP/2.0 200", &copy))
                .await
                .is_err()
            {
                return sent;
            }
        }
    }
}
