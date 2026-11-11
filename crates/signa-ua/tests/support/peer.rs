/*!
Raw peers on loopback, over UDP and TCP, that play the other side of a UA.
*/

use std::{collections::VecDeque, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream, UdpSocket,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::mpsc,
    task::JoinSet,
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
        framed(&mut self.buffer)
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

/// Takes the first whole message out of `buffer`, framed by its
/// Content-Length.
fn framed(buffer: &mut Vec<u8>) -> Option<String> {
    let end = buffer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buffer[..end]).unwrap();
    let length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, value)| value.trim().parse().unwrap());
    let total = end + 4 + length;
    if buffer.len() < total {
        return None;
    }
    let message = buffer.drain(..total).collect();
    Some(String::from_utf8(message).unwrap())
}

/// A raw peer over UDP or TCP that takes the UA's requests as well as its
/// responses, so that a test can hold back an answer and send something
/// that crosses it.
///
/// Over TCP the UA opens connections of its own for its requests (RFC 3261
/// section 18.1.1), so the peer listens at the address its Via and Contact
/// name, and reads every connection the UA opens there besides the one it
/// opened to the UA. What it sends goes on that one, the answers to the UA's
/// requests too. A client transaction takes a response by its branch (RFC
/// 3261 section 17.1.3), so that is enough for these tests, but it leaves
/// out the answer on the connection of the request that a real peer sends
/// (section 18.2.2). Over UDP one socket does all of it. `Wire` stays the
/// peer of tests that never take a request of the UA's.
///
/// A message read but not taken, such as a 100 Trying or the other of two
/// answers, waits for the next receive, so that the order in which the UA
/// sends things that a test does not order matters to no test.
pub(crate) struct Raw {
    transport: &'static str,
    address: SocketAddr,
    out: Out,
    messages: mpsc::UnboundedReceiver<String>,
    stash: VecDeque<String>,
    readers: JoinSet<()>,
}

enum Out {
    Udp { socket: Arc<UdpSocket>, to: SocketAddr },
    Tcp(OwnedWriteHalf),
}

impl Raw {
    /// Starts a peer for `transport`, `UDP` or `TCP`, of the UA at `udp` and
    /// `tcp`.
    pub(crate) async fn start(
        transport: &'static str,
        udp: SocketAddr,
        tcp: SocketAddr,
    ) -> Raw {
        assert!(matches!(transport, "UDP" | "TCP"), "{transport}");
        let (sender, messages) = mpsc::unbounded_channel();
        let mut readers = JoinSet::new();
        let (address, out) = if transport == "UDP" {
            let socket =
                Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let reading = socket.clone();
            readers.spawn(async move {
                let mut buffer = vec![0; 65_536];
                while let Ok((n, _)) = reading.recv_from(&mut buffer).await {
                    let message = String::from_utf8_lossy(&buffer[..n]);
                    if sender.send(message.into_owned()).is_err() {
                        return;
                    }
                }
            });
            (socket.local_addr().unwrap(), Out::Udp { socket, to: udp })
        } else {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (read, write) =
                TcpStream::connect(tcp).await.unwrap().into_split();
            readers.spawn(read_frames(read, sender.clone()));
            readers.spawn(async move {
                let mut connections = JoinSet::new();
                while let Ok((stream, _)) = listener.accept().await {
                    let (read, write) = stream.into_split();
                    let sender = sender.clone();
                    // Nothing goes on this connection, which only has to
                    // stay open.
                    connections.spawn(async move {
                        read_frames(read, sender).await;
                        drop(write);
                    });
                }
            });
            (address, Out::Tcp(write))
        };
        let stash = VecDeque::new();
        Raw { transport, address, out, messages, stash, readers }
    }

    /// The address the peer's Via and Contact name.
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// What a plan's Request-URI takes after `sip:peer@` to reach the peer.
    pub(crate) fn target(&self) -> String {
        if self.transport == "UDP" {
            self.address.to_string()
        } else {
            format!("{};transport=tcp", self.address)
        }
    }

    /// Sends `message`, written for UDP as the message helpers write it.
    /// Its Via takes the peer's transport. Over TCP its Contact gets a
    /// `transport` parameter too, so that the UA's requests come to the
    /// listener. Each line ends in CRLF.
    pub(crate) async fn send(&mut self, message: &str) {
        let via = format!("SIP/2.0/{}", self.transport);
        let plain = format!("Contact: <sip:peer@{}>", self.address);
        let tcp =
            format!("Contact: <sip:peer@{};transport=tcp>", self.address);
        let message = message
            .replace("\r\n", "\n")
            .split('\n')
            .map(|line| {
                if line.starts_with("Via: ") {
                    line.replace("SIP/2.0/UDP", &via)
                } else if self.transport == "TCP" && line == plain {
                    tcp.clone()
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\r\n");
        match &mut self.out {
            Out::Udp { socket, to } => {
                socket.send_to(message.as_bytes(), *to).await.unwrap();
            }
            Out::Tcp(write) => {
                write.write_all(message.as_bytes()).await.unwrap()
            }
        }
    }

    /// Receives the first message from the UA, on any connection, for which
    /// `wanted` holds, first among those read before. The others wait for a
    /// later receive.
    pub(crate) async fn recv_where(
        &mut self,
        wanted: impl Fn(&str) -> bool,
    ) -> String {
        if let Some(i) = self.stash.iter().position(|message| wanted(message))
        {
            return self.stash.remove(i).expect("found");
        }
        let read = async {
            loop {
                let message =
                    self.messages.recv().await.expect("readers running");
                if wanted(&message) {
                    return message;
                }
                self.stash.push_back(message);
            }
        };
        timeout(WAIT, read).await.expect("a message in time")
    }

    /// Receives the first message that starts with `start`.
    pub(crate) async fn recv_starting(&mut self, start: &str) -> String {
        self.recv_where(|message| message.starts_with(start)).await
    }

    /// Receives the first message that starts with `start` and has `cseq`
    /// as its CSeq.
    pub(crate) async fn recv_answer(
        &mut self,
        start: &str,
        cseq: &str,
    ) -> String {
        self.recv_where(|message| {
            message.starts_with(start) && header(message, "CSeq") == [cseq]
        })
        .await
    }

    /// Receives the first final response with `cseq` as its CSeq.
    pub(crate) async fn recv_final(&mut self, cseq: &str) -> String {
        self.recv_where(|message| {
            message.starts_with("SIP/2.0 ")
                && !message.starts_with("SIP/2.0 1")
                && header(message, "CSeq") == [cseq]
        })
        .await
    }

    /// Checks that no message for which `unwanted` holds arrives within
    /// `wait`, or waits among those read before. The rest is dropped.
    pub(crate) async fn quiet_where(
        &mut self,
        unwanted: impl Fn(&str) -> bool,
        wait: Duration,
    ) {
        let transport = self.transport;
        for message in self.stash.drain(..) {
            assert!(!unwanted(&message), "{transport}: unexpected {message}");
        }
        let _ = timeout(wait, async {
            while let Some(message) = self.messages.recv().await {
                assert!(
                    !unwanted(&message),
                    "{transport}: unexpected {message}"
                );
            }
        })
        .await;
    }

    /// Checks that nothing starting with `start` arrives within `wait`.
    pub(crate) async fn quiet(&mut self, start: &str, wait: Duration) {
        self.quiet_where(|message| message.starts_with(start), wait).await;
    }

    /// Drops what arrives within `wait`, and what waits, such as a copy
    /// already on its way.
    pub(crate) async fn drain(&mut self, wait: Duration) {
        self.quiet_where(|_| false, wait).await;
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        self.readers.abort_all();
    }
}

/// Sends each message read off `read` to `sender`, until either closes.
async fn read_frames(
    mut read: OwnedReadHalf,
    sender: mpsc::UnboundedSender<String>,
) {
    let mut buffer = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        while let Some(message) = framed(&mut buffer) {
            if sender.send(message).is_err() {
                return;
            }
        }
        match read.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
    }
}
