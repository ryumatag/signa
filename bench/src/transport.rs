use std::{
    hint::black_box as bb,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use bytes::{Bytes, BytesMut};
use criterion::Criterion;
use signa::{
    bench::{tcp, udp, Flow, Transport},
    transport::WriteLimits,
    Message,
};
use tokio::{runtime, sync::mpsc};

use crate::{
    benchmark,
    message::{REQUEST_TYPICAL, RESPONSE_TYPICAL},
};

const LOCALHOST: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

fn runtime() -> runtime::Runtime {
    runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

pub(super) fn write_admission(c: &mut Criterion) {
    let rt = runtime();
    for (variant, messages) in [("messages", 1), ("bytes", 2)] {
        let (writer, _peer) = rt.block_on(async {
            let listener =
                tokio::net::TcpListener::bind(LOCALHOST).await.unwrap();
            let (inbound, _received) = mpsc::channel(4);
            let config = tcp::Config {
                write_limits: WriteLimits { messages, bytes: 3 },
                ..tcp::Config::default()
            };
            let (_, writer) = tcp::connect(
                listener.local_addr().unwrap(),
                &config,
                &inbound,
            )
            .await
            .unwrap();
            let (peer, _) = listener.accept().await.unwrap();
            // Keep the inbound receiver with the peer so the reader stays
            // open.
            (writer, (peer, _received))
        });
        writer.send(Bytes::from_static(b"abc")).unwrap();

        // No runtime progress during measurement. The first write remains
        // queued, making count and byte saturation independent of socket
        // timing.
        benchmark(
            c,
            format!("reject/transport/tcp_write/{variant}"),
            1,
            |b| {
                b.iter(|| {
                    assert_eq!(
                        writer.send(bb(Bytes::from_static(b"d"))),
                        Err(tcp::SendError::Full)
                    );
                });
            },
        );
    }
}

// A request and its response over the loopback, through the transport alone.
// The server side answers without parsing, so this is the cost of the syscalls
// and signa's buffer handling.
pub(super) fn udp(c: &mut Criterion) {
    let rt = runtime();
    let (client, server) = rt.block_on(async {
        (
            udp::Socket::bind(LOCALHOST).unwrap(),
            udp::Socket::bind(LOCALHOST).unwrap(),
        )
    });
    let to_server = Flow {
        transport: Transport::Udp,
        local: client.local_addr(),
        remote: server.local_addr(),
    };
    let mut client_buf = BytesMut::new();
    let mut server_buf = BytesMut::new();
    let len = (REQUEST_TYPICAL.len() + RESPONSE_TYPICAL.len()) as u64;

    benchmark(c, "transport/udp/round_trip", len, |b| {
        b.iter(|| {
            rt.block_on(async {
                client.send(bb(REQUEST_TYPICAL), &to_server).await.unwrap();
                let (request, flow) =
                    server.recv(&mut server_buf).await.unwrap();
                assert_eq!(request.len(), REQUEST_TYPICAL.len());
                server.send(bb(RESPONSE_TYPICAL), &flow).await.unwrap();
                let (response, _) =
                    client.recv(&mut client_buf).await.unwrap();
                assert_eq!(response.len(), RESPONSE_TYPICAL.len());
            });
        });
    });
}

// The same over one TCP connection. Each direction goes through the writer
// queue, the socket, the decoder, and the inbound channel, so the messages are
// parsed on the way.
pub(super) fn tcp(c: &mut Criterion) {
    let rt = runtime();
    let (server_tx, mut server_rx) = mpsc::channel(4);
    let (client_tx, mut client_rx) = mpsc::channel(4);
    let config = tcp::Config::default();
    let client = rt.block_on(async {
        let listener =
            tcp::Listener::bind(LOCALHOST, config, server_tx).unwrap();
        let addr = listener.local_addr();
        let (_, accepted) = tokio::join!(
            listener.accept(),
            tcp::connect(addr, &config, &client_tx)
        );
        let (_, writer) = accepted.unwrap();
        writer
    });
    let request = Bytes::from_static(REQUEST_TYPICAL);
    let response = Bytes::from_static(RESPONSE_TYPICAL);
    let len = (REQUEST_TYPICAL.len() + RESPONSE_TYPICAL.len()) as u64;

    benchmark(c, "transport/tcp/round_trip", len, |b| {
        b.iter(|| {
            rt.block_on(async {
                client.send(bb(request.clone())).unwrap();
                let inbound = server_rx.recv().await.unwrap();
                assert!(matches!(inbound.message, Message::Request(_)));
                inbound.writer.send(bb(response.clone())).unwrap();
                let inbound = client_rx.recv().await.unwrap();
                assert!(matches!(inbound.message, Message::Response(_)));
            });
        });
    });

    benchmark(c, "transport/tcp/round_trip_receipts", len, |b| {
        b.iter(|| {
            rt.block_on(async {
                client.submit(bb(request.clone())).unwrap().await.unwrap();
                let inbound = server_rx.recv().await.unwrap();
                assert!(matches!(inbound.message, Message::Request(_)));
                inbound
                    .writer
                    .submit(bb(response.clone()))
                    .unwrap()
                    .await
                    .unwrap();
                let inbound = client_rx.recv().await.unwrap();
                assert!(matches!(inbound.message, Message::Response(_)));
            });
        });
    });

    // Exceed each inbound channel's capacity. A reader waiting on the
    // consumer must not prevent the same connection's writer from running.
    benchmark(c, "transport/tcp/burst", len * 8, |b| {
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..8 {
                    client.send(bb(request.clone())).unwrap();
                }
                for _ in 0..8 {
                    let inbound = server_rx.recv().await.unwrap();
                    assert!(matches!(inbound.message, Message::Request(_)));
                    inbound.writer.send(bb(response.clone())).unwrap();
                }
                for _ in 0..8 {
                    let inbound = client_rx.recv().await.unwrap();
                    assert!(matches!(inbound.message, Message::Response(_)));
                }
            });
        });
    });
}
