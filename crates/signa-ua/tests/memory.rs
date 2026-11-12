/*!
What the UA keeps and allocates, measured by the allocator.

signa-core hands each message over as slices of the buffer it was read into.
Over UDP that buffer is a chunk of 256 KiB that several datagrams share, and
over TCP the read buffer of the connection, so a small message the UA keeps
for long could keep a far larger allocation alive. These tests count the bytes
allocated and not yet freed in this process, which is why they have a binary
of their own.

They also measure what the UA keeps once its tables are full, and what a call
allocates in steady state. Those two take several seconds each, so they are
ignored unless asked for, as `scripts/test-packages --include-ignored` does.
Each prints its numbers, which
`cargo test -p signa-ua --test memory -- --include-ignored --nocapture` shows. The bounds they
assert are generous, so that they catch a leak or a buffer kept by mistake,
not a few bytes more.
*/

// Every test binds loopback sockets, which Miri does not provide.
#![cfg(not(miri))]

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
    transaction::Timers,
};
use signa_ua::{
    Config, Description, Event, IncomingInvite, InvitePlan, Ua, UaEvents,
    attach,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};

/// Counts the bytes allocated and not yet freed, and every allocation.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

/// How many allocations and reallocations there were, and the bytes they
/// asked for.
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

// SAFETY: Each method passes its arguments on to `System` unchanged, so it
// keeps the contract `System` keeps. The counter is only arithmetic beside it.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller keeps the contract of `GlobalAlloc::alloc`.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
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
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED.fetch_add(size, Ordering::Relaxed);
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

fn sdp() -> Description {
    Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from_static(b"v=0\r\n"),
    )
}

/// Short timers, so that every transaction and replay context of a call
/// ends within a second or two. 64 T1 is 1.28 s, and Timer K is T4.
fn short() -> Timers {
    Timers::builder()
        .t1(Duration::from_millis(20))
        .t2(Duration::from_millis(80))
        .t4(Duration::from_millis(100))
        .build()
        .unwrap()
}

/// A UA on its own UDP endpoint with [`short`] timers, `limits` applied to
/// its configuration, and its address.
fn ua_on_udp(limits: fn(Config) -> Config) -> (Ua, SocketAddr) {
    let (endpoint, incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .timers(short())
        .bind()
        .unwrap();
    let address = endpoint.udp_addr().unwrap();
    let contact = format!("sip:ua@{address}");
    let config = limits(Config::new(&contact).unwrap().timers(short()));
    (attach(endpoint, incoming, config).unwrap(), address)
}

/// The next event for which `wanted` gives something.
async fn event<T>(
    events: &mut UaEvents,
    wanted: impl Fn(Event) -> Option<T>,
) -> T {
    loop {
        let event = timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("an event in time")
            .expect("the UA runs");
        if let Some(found) = wanted(event) {
            return found;
        }
    }
}

/// Drops the events that came, so that the queue holds none of them.
async fn drain(events: &mut UaEvents) {
    while timeout(Duration::from_millis(20), events.recv()).await.is_ok() {}
}

/// The value of the header `name` in `message`.
fn header<'a>(message: &'a str, name: &str) -> &'a str {
    message
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .expect("the header is there")
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
/// bytes then allocated, once two readings 200 ms apart agree to within a
/// KiB, so that a late timer on a loaded machine is waited for.
async fn settled() -> usize {
    let mut last = LIVE.load(Ordering::Relaxed);
    for _ in 0..50 {
        sleep(Duration::from_millis(200)).await;
        let now = LIVE.load(Ordering::Relaxed);
        if now.abs_diff(last) < 1024 {
            return now;
        }
        last = now;
    }
    last
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

/// How long the transactions and replay contexts of [`short`] timers last
/// at most: 64 T1, and a little.
const LINGER: Duration = Duration::from_millis(1_500);

/// How many sessions and undecided INVITEs fill the tables of the UA that
/// [`memory_stops_growing_at_the_limits`] measures.
const FULL: usize = 16;

/// What a flood after the first may add, under a tenth of what its 160
/// INVITEs of about 400 bytes would keep if each kept its bytes, and three
/// times the most seen between floods.
const FLOOD_GROWTH: usize = 32 * 1024;

/// The UA keeps a bounded amount once its tables are full. A peer fills
/// them with `FULL` acknowledged sessions and `FULL` INVITEs the
/// application holds, and then three times sends ten times as many
/// INVITEs, which the UA answers with a 503, since no room is left for a
/// decision. The first flood may grow the tables of the endpoint and the UA
/// by less than a KiB for each INVITE, and the later floods add less than
/// [`FLOOD_GROWTH`].
///
/// An INVITE without a final response keeps the 256 KiB chunk it arrived in
/// alive, as signa-core's transaction keeps slices of it. The held INVITEs
/// arrived in one chunk. The endpoint moves on to a new chunk once less
/// than 64 KiB is left in the old one, so the peer sends filler datagrams
/// until it has, and the floods start with that chunk kept and do not cross
/// into it.
#[tokio::test]
#[ignore = "takes about 8 s, scripts/test-packages --include-ignored runs it"]
async fn memory_stops_growing_at_the_limits() {
    let _alone = ALONE.lock().await;

    let (mut ua, address) = ua_on_udp(|config| {
        config
            .max_dialogs(FULL)
            .max_pending_invites(FULL)
            .decision_timeout(Duration::from_secs(60))
    });
    tokio::spawn(ua.driver);
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = peer.local_addr().unwrap();
    let mut buffer = vec![0; 65_536];
    let filler = vec![b'x'; 8000];
    let mut held: Vec<IncomingInvite> = Vec::with_capacity(FULL);
    let mut floods = Vec::with_capacity(3);
    let before = settled().await;

    for call in 0..FULL {
        let message = invite("UDP", local, call);
        peer.send_to(message.as_bytes(), address).await.unwrap();
        let incoming = event(&mut ua.events, |event| match event {
            Event::Invite(invite) => Some(invite),
            _ => None,
        })
        .await;
        incoming.try_accept(sdp()).unwrap().await.unwrap();
        // A copy of the 2xx of the call before may still come.
        let call_id = format!("memory-{call}");
        let ok = loop {
            let read =
                timeout(Duration::from_secs(5), peer.recv_from(&mut buffer));
            let (n, _) = read.await.expect("a 2xx in time").unwrap();
            let message = String::from_utf8(buffer[..n].to_vec()).unwrap();
            if message.starts_with("SIP/2.0 200")
                && header(&message, "Call-ID") == call_id
            {
                break message;
            }
        };
        let ack = format!(
            "ACK sip:ua@{address} SIP/2.0\r
Via: SIP/2.0/UDP {local};branch=z9hG4bK-ack-{call}\r
Max-Forwards: 70\r
To: {to}\r
From: <sip:peer@{local}>;tag=peer-{call}\r
Call-ID: {call_id}\r
CSeq: 1 ACK\r
Content-Length: 0\r
\r
",
            to = header(&ok, "To"),
        );
        peer.send_to(ack.as_bytes(), address).await.unwrap();
    }

    for call in FULL..2 * FULL {
        let message = invite("UDP", local, call);
        peer.send_to(message.as_bytes(), address).await.unwrap();
        held.push(
            event(&mut ua.events, |event| match event {
                Event::Invite(invite) => Some(invite),
                _ => None,
            })
            .await,
        );
    }
    // The transactions of the accepted INVITEs end at Timer L, 64 T1. Those
    // of the held ones stay in Proceeding.
    sleep(LINGER).await;
    drain(&mut ua.events).await;
    let full = settled().await.saturating_sub(before);

    let mut pinned = full;
    for _ in 0..80 {
        if pinned > full + 200 * 1024 {
            break;
        }
        for _ in 0..8 {
            peer.send_to(&filler, address).await.unwrap();
            sleep(Duration::from_millis(1)).await;
        }
        pinned = settled().await.saturating_sub(before);
    }
    assert!(
        pinned > full + 200 * 1024,
        "the endpoint kept the chunk of the held INVITEs as its own: \
         {pinned} bytes, {full} before",
    );

    for round in 0..3 {
        for call in 0..10 * FULL {
            let call = (2 + 10 * round) * FULL + call;
            let message = invite("UDP", local, call);
            peer.send_to(message.as_bytes(), address).await.unwrap();
            sleep(Duration::from_millis(1)).await;
        }
        // The 503s end at Timer H, 64 T1, as the peer sends no ACK.
        sleep(LINGER).await;
        drain(&mut ua.events).await;
        floods.push(settled().await.saturating_sub(before));
    }

    eprintln!(
        "full tables: {full} bytes for {FULL} sessions and {FULL} undecided \
         INVITEs, {} per entry; {pinned} with the chunk of the undecided \
         INVITEs left behind; after each flood of {} refused INVITEs: \
         {floods:?} bytes",
        full / (2 * FULL),
        10 * FULL,
    );
    assert!(full < 2 * FULL * PER_INVITE, "{full} bytes with full tables");
    assert!(
        floods[0] < pinned + 10 * FULL * 1024,
        "{} bytes after the first flood, {pinned} before",
        floods[0],
    );
    let most = *floods.iter().max().unwrap();
    assert!(
        most < floods[0] + FLOOD_GROWTH,
        "{floods:?} bytes after the floods",
    );
    drop(held);
}

/// The dialog limit of the UAs that make calls. A caller keeps an attempt
/// and the replay context of its 2xx, which come four to a dialog, until
/// the core stops collecting responses at 64 T1. The warm-up is below four
/// times this, so a call never meets those limits, however fast the calls
/// go.
const DIALOGS: usize = 128;

/// Calls made before the measured ones. The tables and maps of the UAs and
/// their endpoints grow to the calls under way within 64 T1, and keep that
/// capacity, and the UAs keep why the last sessions ended, as many as the
/// dialog limit. The warm-up lets both reach their size.
const WARM_UP: usize = 300;

const _: () = assert!(DIALOGS < WARM_UP && WARM_UP < 4 * DIALOGS);

/// Calls in each measured round.
const CALLS: usize = 100;

/// How much the bytes kept after a round may differ from those after
/// another, ten bytes a call over the two rounds between the first and the
/// last. The rounds have differed by a few hundred bytes.
const ROUND_SPREAD: isize = 2 * 1024;

/// A call between two UAs in this process, from the caller's INVITE to its
/// BYE, keeps nothing that grows with the number of calls. After the
/// warm-up, three rounds of calls keep within [`ROUND_SPREAD`] of each
/// other, and allocate within a tenth of each other.
///
/// The numbers it prints count every allocation in the process while the
/// calls run: both UAs and endpoints, the runtime under them, and the
/// test's own plans and waits. A reallocation counts its new size. They are
/// not a cost claimed of the UA.
#[tokio::test]
#[ignore = "takes about 8 s, scripts/test-packages --include-ignored runs it"]
async fn rounds_of_calls_keep_what_the_first_kept() {
    let _alone = ALONE.lock().await;

    let limits =
        |config: Config| config.max_dialogs(DIALOGS).max_attempts(4 * DIALOGS);
    let (Ua { handle: caller, events: mut caller_events, driver }, _) =
        ua_on_udp(limits);
    tokio::spawn(driver);
    let (Ua { handle: _callee, events: mut callee_events, driver }, address) =
        ua_on_udp(limits);
    tokio::spawn(driver);
    let target: signa_core::Uri = format!("sip:ua@{address}").parse().unwrap();
    let from: signa_core::Uri = "sip:caller@127.0.0.1".parse().unwrap();
    let call = async |caller_events: &mut UaEvents,
                      callee_events: &mut UaEvents| {
        let plan = InvitePlan::new(target.clone(), from.clone(), sdp());
        caller.try_invite(plan).unwrap().await.unwrap();
        let incoming = event(callee_events, |event| match event {
            Event::Invite(invite) => Some(invite),
            _ => None,
        })
        .await;
        incoming.try_accept(sdp()).unwrap().await.unwrap();
        let calling = event(caller_events, |event| match event {
            Event::Confirmed { session, .. } => Some(session),
            _ => None,
        })
        .await;
        caller.try_terminate(&calling).unwrap().await.unwrap();
        event(callee_events, |event| match event {
            Event::Ended { .. } => Some(()),
            _ => None,
        })
        .await;
    };
    let mut rounds = Vec::with_capacity(3);
    let mut counts = Vec::with_capacity(3);

    for _ in 0..WARM_UP {
        call(&mut caller_events, &mut callee_events).await;
    }
    sleep(LINGER).await;
    drain(&mut caller_events).await;
    drain(&mut callee_events).await;
    let before = settled().await;

    for _ in 0..3 {
        let allocations = ALLOCATIONS.load(Ordering::Relaxed);
        let allocated = ALLOCATED.load(Ordering::Relaxed);
        for _ in 0..CALLS {
            call(&mut caller_events, &mut callee_events).await;
        }
        counts.push((
            ALLOCATIONS.load(Ordering::Relaxed) - allocations,
            ALLOCATED.load(Ordering::Relaxed) - allocated,
        ));
        sleep(LINGER).await;
        drain(&mut caller_events).await;
        drain(&mut callee_events).await;
        rounds.push(settled().await as isize - before as isize);
    }

    let per_call: Vec<(usize, usize)> = counts
        .iter()
        .map(|&(allocations, allocated)| {
            (allocations / CALLS, allocated / CALLS)
        })
        .collect();
    eprintln!(
        "per call in this process, in each round: {per_call:?} allocations \
         and bytes; kept after each round of {CALLS} calls, against the \
         warm-up: {rounds:?} bytes",
    );
    let least = *rounds.iter().min().unwrap();
    let most = *rounds.iter().max().unwrap();
    assert!(most - least < ROUND_SPREAD, "{rounds:?} bytes after the rounds");
    // A chunk of 256 KiB kept by mistake would show here, apart from the
    // spread.
    assert!(most < 256 * 1024, "{rounds:?} bytes kept after the rounds");
    let fewest = counts.iter().map(|&(allocations, _)| allocations).min();
    let most_allocations =
        counts.iter().map(|&(allocations, _)| allocations).max();
    assert!(
        most_allocations.unwrap() < fewest.unwrap() * 11 / 10,
        "{per_call:?} allocations and bytes a call",
    );
}
