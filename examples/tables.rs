/*!
Runs many round trips on RFC timers, so that every transaction is still in the
tables at the end, and prints how long each took. `scripts/tables` runs it
under `/usr/bin/time` for the maximum RSS, and with a second argument it waits
with the tables full for `heap -s`.
*/

#![allow(unreachable_code)]

use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Instant,
};

use bytes::Bytes;
use signa::{
    endpoint::Endpoint, transport::Transport, Request, Response, StatusCode,
};
use tower_service::Service;

const LOCALHOST: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

fn request() -> Request<Bytes> {
    Request::builder()
        .method("OPTIONS")
        .uri("sip:bob@biloxi.example.com")
        .header("From", "Alice <sip:alice@atlanta.example.com>;tag=1928301774")
        .header("To", "Bob <sip:bob@biloxi.example.com>")
        .header("Call-ID", "a84b4c76e66710@pc33.atlanta.example.com")
        .header("CSeq", "314159 OPTIONS")
        .header("Max-Forwards", "70")
        .body(Bytes::new())
        .unwrap()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let total: usize =
        std::env::args().nth(1).map_or(200_000, |n| n.parse().unwrap());
    let in_flight = 16;

    let service = tower::service_fn(|request: Request<Bytes>| async move {
        let response = Response::reply_to(&request)
            .status(StatusCode::OK)
            .body(Bytes::new())
            .unwrap();
        Ok::<_, Infallible>(response)
    });

    // Retain every response for Timer J instead of measuring overload.
    let server = Endpoint::builder()
        .udp(LOCALHOST)
        .max_server_transactions(1 << 24)
        .serve(service)
        .unwrap();
    let client_end = Endpoint::builder()
        .udp(LOCALHOST)
        .max_client_transactions(1 << 24)
        .serve(tower::service_fn(|_: Request<Bytes>| async move {
            Err::<Response<Bytes>, Infallible>(unreachable!())
        }))
        .unwrap();
    let client = client_end.client(Transport::Udp, server.udp_addr().unwrap());

    let started = Instant::now();

    let mut tasks = Vec::new();
    for _ in 0..in_flight {
        let mut client = client.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..total / in_flight {
                let response = client.call(request()).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }

    let elapsed = started.elapsed();

    println!(
        "{total} round trips in {elapsed:.2?}, {:.1} us each",
        elapsed.as_secs_f64() * 1e6 / total as f64
    );

    // Wait with the tables full, for `heap`.
    if std::env::args().nth(2).is_some() {
        println!("pid {}", std::process::id());
        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
    }
}
