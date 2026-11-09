/*!
Runs many transactions on RFC 3261 timers, so that every one of them is still
in the tables at the end, and prints how long each took. `scripts/tables` runs
it under `/usr/bin/time` for the maximum RSS, and with a second argument it
waits with the tables full for `heap -s`.

`SIGNA_TABLES_MODE` picks what each transaction is, all over UDP:

* `options`, the default: an OPTIONS answered with a 200. The server keeps a
  Completed entry with its 200 for Timer J (32 s), and the client a Completed
  entry for Timer K (5 s).
* `invite`: an INVITE answered with a 200, which the UAC acknowledges with
  `send_request`. Both sides keep an entry in Accepted, the server for
  Timer L and the client for Timer M, 32 s each. Neither retains the 2xx.
* `reject`: an INVITE answered with a 486. The client keeps a Completed entry
  with the ACK it built for Timer D (32 s). The server keeps a Confirmed entry
  for Timer I (T4, 5 s) once that ACK arrives.

Set `SIGNA_TABLES_OBSERVE=1` to keep each server transaction's
`ServerEvents` and each client transaction's `ClientControl` and `Responses`
as well. Otherwise the TU drops them, and the machines stay anyway.

The run reports whether it ended before the shortest of these timers, which
means every transaction it made was still live when it finished. Each table
also reserves room for a CANCEL per INVITE, which is not counted as a live
entry.
*/

#![allow(unreachable_code)]

use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytes::Bytes;
use signa::{
    endpoint::{Endpoint, IncomingEvent, Target, ViaMode},
    message::header::{CALL_ID, FROM, TO},
    transaction::Timers,
    transport::{Transport, WriteLimits},
    Request, Response, StatusCode,
};

const LOCALHOST: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Options,
    Invite,
    Reject,
}

impl Mode {
    fn from_env() -> Mode {
        match env::var("SIGNA_TABLES_MODE").as_deref() {
            Err(_) | Ok("options") => Mode::Options,
            Ok("invite") => Mode::Invite,
            Ok("reject") => Mode::Reject,
            Ok(other) => panic!("unknown SIGNA_TABLES_MODE {other}"),
        }
    }

    fn method(self) -> &'static str {
        match self {
            Mode::Options => "OPTIONS",
            Mode::Invite | Mode::Reject => "INVITE",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Mode::Options | Mode::Invite => StatusCode::OK,
            Mode::Reject => StatusCode::from_u16(486).unwrap(),
        }
    }

    /// What the tables keep, and the timer that removes the first entries.
    fn retention(self, timers: &Timers) -> (&'static str, Duration) {
        match self {
            Mode::Options => {
                ("server Completed (J), client Completed (K)", timers.t4())
            }
            Mode::Invite => {
                ("server Accepted (L), client Accepted (M)", 64 * timers.t1())
            }
            Mode::Reject => (
                "server Confirmed (I), client Completed (D) with its ACK",
                timers.t4(),
            ),
        }
    }
}

fn request(method: &str) -> Request<Bytes> {
    Request::builder()
        .method(method)
        .uri("sip:bob@biloxi.example.com")
        .header("From", "Alice <sip:alice@atlanta.example.com>;tag=1928301774")
        .header("To", "Bob <sip:bob@biloxi.example.com>")
        .header("Call-ID", "a84b4c76e66710@pc33.atlanta.example.com")
        .header("CSeq", format!("314159 {method}").as_str())
        .header("Max-Forwards", "70")
        .body(Bytes::new())
        .unwrap()
}

/// The ACK a UAC core builds for a 2xx.
fn ack_for(ok: &Response<Bytes>) -> Request<Bytes> {
    let headers = ok.headers();
    Request::builder()
        .method("ACK")
        .uri("sip:bob@biloxi.example.com")
        .header(FROM, headers.get(FROM).unwrap().clone())
        .header(TO, headers.get(TO).unwrap().clone())
        .header(CALL_ID, headers.get(CALL_ID).unwrap().clone())
        .header("CSeq", "314159 ACK")
        .header("Max-Forwards", "70")
        .body(Bytes::new())
        .unwrap()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let total: usize =
        env::args().nth(1).map_or(200_000, |n| n.parse().unwrap());
    let in_flight = 16;
    let mode = Mode::from_env();
    let observed = env::var_os("SIGNA_TABLES_OBSERVE").is_some();
    let timers = Timers::default();
    let unbounded = WriteLimits { messages: usize::MAX, bytes: usize::MAX };

    // Retain every transaction for its timers instead of measuring overload.
    let (server, mut incoming) = Endpoint::builder()
        .udp(LOCALHOST)
        .timers(timers)
        .max_server_transactions(1 << 24)
        .max_server_response_bytes(usize::MAX)
        .bind()
        .unwrap();
    let response_len = Arc::new(Mutex::new(0));
    let measured = response_len.clone();
    tokio::spawn(async move {
        let mut observations =
            if observed { Vec::with_capacity(total) } else { Vec::new() };
        while let Some(event) = incoming.recv().await {
            // ACKs for a 2xx arrive here and need nothing more.
            let IncomingEvent::Request(envelope) = event else { continue };
            let (responder, events) = envelope.transaction.into_parts();
            if observed {
                observations.push(events);
            } else {
                drop(events);
            }
            // A fixed tag keeps the random source out of the measurement. A
            // real UAS uses `Tag::random`.
            let response = Response::reply_to(&envelope.request)
                .status(mode.status())
                .to_tag("tables")
                .body(Bytes::new())
                .unwrap();
            *measured.lock().unwrap() = response.to_bytes().len();

            responder.respond(response).await.unwrap();
        }
    });
    let (client_end, _incoming) = Endpoint::builder()
        .udp(LOCALHOST)
        .timers(timers)
        .max_client_transactions(1 << 24)
        .max_client_handles(1 << 24)
        .client_response_budget(unbounded)
        .bind()
        .unwrap();
    let target = Target::new(Transport::Udp, server.udp_addr().unwrap());

    let started = Instant::now();

    let mut tasks = Vec::new();
    for _ in 0..in_flight {
        let client = client_end.clone();
        tasks.push(tokio::spawn(async move {
            let mut kept = Vec::new();
            for _ in 0..total / in_flight {
                let (control, mut responses) = client
                    .start(request(mode.method()), target)
                    .await
                    .unwrap()
                    .into_parts();
                let mut response = responses.next().await.unwrap().unwrap();
                while response.status().is_provisional() {
                    response = responses.next().await.unwrap().unwrap();
                }
                assert_eq!(response.status(), mode.status());
                if mode == Mode::Invite {
                    client
                        .send_request(
                            ack_for(&response),
                            target,
                            ViaMode::Fresh,
                        )
                        .await
                        .unwrap();
                }
                if observed {
                    kept.push((control, responses));
                }
            }
            kept
        }));
    }
    let mut kept = Vec::new();
    for task in tasks {
        kept.push(task.await.unwrap());
    }

    let elapsed = started.elapsed();
    let (states, retention) = mode.retention(&timers);
    let made = total / in_flight * in_flight;

    println!(
        "{made} round trips in {elapsed:.2?}, {:.1} us each",
        elapsed.as_secs_f64() * 1e6 / made as f64
    );
    println!(
        "{made} {} over UDP, {} B request, {} B response, {}",
        mode.method(),
        request(mode.method()).to_bytes().len(),
        response_len.lock().unwrap(),
        if observed { "handles kept" } else { "handles dropped" },
    );
    if elapsed < retention {
        println!("live: {states}, all {made} on each side");
    } else {
        println!(
            "live: {states}, but the run outlasted {retention:?}, so the \
             first entries have left"
        );
    }

    // Wait with the tables full, for `heap`.
    if env::args().nth(2).is_some() {
        println!("pid {}", std::process::id());
        tokio::time::sleep(Duration::from_secs(20)).await;
    }
    drop(kept);
}
