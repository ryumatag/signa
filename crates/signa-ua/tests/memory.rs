/*!
What the UA keeps of the messages it receives, measured by the allocator.

signa-core hands each message over as slices of the buffer it was read into.
Over UDP that buffer is a chunk of 256 KiB that several datagrams share, and
over TCP the read buffer of the connection, so a small message the UA keeps
for long could keep a far larger allocation alive. These tests count the bytes
allocated and not yet freed in this process, which is why they have a binary
of their own.
*/

use std::{
    alloc::{GlobalAlloc, Layout, System},
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use bytes::Bytes;
use signa_core::{
    HeaderValue,
    endpoint::{Endpoint, Incoming},
};
use signa_ua::{Config, Description, Event, Ua, UaEvents, attach};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};

/// Counts the bytes allocated and not yet freed.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: Each method passes its arguments on to `System` unchanged, so it
// keeps the contract `System` keeps. The counter is only arithmetic beside it.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller keeps the contract of `GlobalAlloc::alloc`.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The caller keeps the contract of `GlobalAlloc::dealloc`.
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(
        &self,
        pointer: *mut u8,
        layout: Layout,
        size: usize,
    ) -> *mut u8 {
        // SAFETY: The caller keeps the contract of `GlobalAlloc::realloc`.
        let moved = unsafe { System.realloc(pointer, layout, size) };
        if !moved.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            LIVE.fetch_add(size, Ordering::Relaxed);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Taken by each test for its whole run, so that a test added beside it does
/// not count its allocations.
static ALONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// How many accepted INVITEs each transport keeps waiting for their ACK.
const HELD: usize = 32;

/// The most each of them may keep allocated, with all that comes with it:
/// its records in the UA and the endpoint, and its 2xx. An INVITE of these
/// tests is about 400 bytes, and the chunk a UDP datagram is read into is
/// 256 KiB.
const PER_INVITE: usize = 16 * 1024;

fn invite(transport: &str, peer: SocketAddr, call: usize) -> String {
    format!(
        "INVITE sip:ua@127.0.0.1 SIP/2.0\r
Via: SIP/2.0/{transport} {peer};branch=z9hG4bK-{call}\r
Max-Forwards: 70\r
To: <sip:ua@127.0.0.1>\r
From: <sip:peer@{peer}>;tag=peer-{call}\r
Call-ID: memory-{call}\r
CSeq: 1 INVITE\r
Contact: <sip:peer@{peer}>\r
Content-Type: application/sdp\r
Content-Length: 5\r
\r
v=0\r
"
    )
}

fn start(endpoint: Endpoint, incoming: Incoming) -> Ua {
    let config = Config::new("sip:ua@127.0.0.1").unwrap();
    attach(endpoint, incoming, config).unwrap()
}

/// Accepts `HELD` INVITEs, and waits until the endpoint has each 2xx. The
/// endpoint then keeps nothing of the INVITE but a copy of its reply route,
/// and the UA keeps it to send the 2xx again until the ACK, which none of
/// them gets.
async fn accept_all(events: &mut UaEvents) {
    let answer = Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from_static(b"v=0\r\n"),
    );
    let mut accepted = 0;
    while accepted < HELD {
        let event = timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("an event in time")
            .expect("the UA runs");
        if let Event::Invite(invite) = event {
            let operation = invite.try_accept(answer.clone()).unwrap();
            operation.await.unwrap();
            accepted += 1;
        }
    }
}

/// Lets the endpoint and the UA finish with what arrived, and returns the
/// bytes then allocated.
async fn settled() -> usize {
    sleep(Duration::from_millis(200)).await;
    LIVE.load(Ordering::Relaxed)
}

/// An accepted INVITE that waits for its ACK keeps its own bytes, which the
/// byte limit of the INVITEs counts, not the buffer it arrived in. Over UDP
/// each INVITE arrives in a chunk of its own, followed by datagrams that fill
/// the rest of the chunk and that the endpoint drops. Over TCP each arrives
/// behind a large OPTIONS in the same read, so that the connection's read
/// buffer has grown when the INVITE is cut from it.
#[tokio::test]
async fn replay_byte_limit_accounts_for_retained_allocations() {
    let _alone = ALONE.lock().await;

    let (endpoint, incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .bind()
        .unwrap();
    let address = endpoint.udp_addr().unwrap();
    let mut ua = start(endpoint, incoming);
    tokio::spawn(ua.driver);
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let filler = vec![b'x'; 8000];
    let before = settled().await;

    for call in 0..HELD {
        let message = invite("UDP", peer.local_addr().unwrap(), call);
        peer.send_to(message.as_bytes(), address).await.unwrap();
        for _ in 0..32 {
            peer.send_to(&filler, address).await.unwrap();
        }
        // Lets the endpoint read the datagrams before the socket's buffer
        // drops any.
        sleep(Duration::from_millis(5)).await;
    }
    accept_all(&mut ua.events).await;

    let grown = settled().await.saturating_sub(before);
    assert!(grown < HELD * PER_INVITE, "UDP: {grown} bytes for {HELD}");

    let (endpoint, incoming) = Endpoint::builder()
        .tcp("127.0.0.1:0".parse().unwrap())
        .bind()
        .unwrap();
    let address = endpoint.tcp_addr().unwrap();
    let mut ua = start(endpoint, incoming);
    tokio::spawn(ua.driver);
    let mut peer = TcpStream::connect(address).await.unwrap();
    let local = peer.local_addr().unwrap();
    let body = "x".repeat(48 * 1024);
    let before = settled().await;

    for call in 0..HELD {
        let options = format!(
            "OPTIONS sip:ua@127.0.0.1 SIP/2.0\r
Via: SIP/2.0/TCP {local};branch=z9hG4bK-options-{call}\r
Max-Forwards: 70\r
To: <sip:ua@127.0.0.1>\r
From: <sip:peer@{local}>;tag=options-{call}\r
Call-ID: options-{call}\r
CSeq: 1 OPTIONS\r
Content-Type: text/plain\r
Content-Length: {}\r
\r
{body}",
            body.len(),
        );
        let message = options + &invite("TCP", local, call);
        peer.write_all(message.as_bytes()).await.unwrap();
    }
    accept_all(&mut ua.events).await;

    let grown = settled().await.saturating_sub(before);
    assert!(grown < HELD * PER_INVITE, "TCP: {grown} bytes for {HELD}");
    drop(peer);
}
