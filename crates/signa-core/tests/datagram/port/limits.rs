/*!
A port's write limits, which its endpoints and raw sends share.
*/

use std::time::Duration;

use bytes::Bytes;
use signa_core::{
    endpoint::{Endpoint, port::DatagramPort},
    transport::Limits,
};
use tokio::time::{sleep, timeout};

use crate::datagram::{
    port::{intercept, upstream},
    send_options,
    wire::{Wire, Writes},
};

// Raw sends take three quarters of a port's write limits, rounded down, so
// a byte limit whose share is below the backend's largest payload would
// refuse a raw send that large as busy however idle the port was. The port
// refuses that configuration. 1963 bytes leave a share of 1473.
#[tokio::test]
async fn the_port_s_write_limits_must_hold_a_whole_payload() {
    for (bytes, valid) in [(1000, false), (1472, false), (1963, true)] {
        let bound = DatagramPort::builder()
            .udp_io(Wire::default())
            .write_limits(Limits { count: 1, bytes })
            .intercept();

        match bound {
            Ok(_) => assert!(valid, "{bytes}"),
            Err(error) => {
                assert!(!valid && error.is_invalid_config(), "{bytes}");
                assert!(
                    error
                        .to_string()
                        .starts_with("invalid port configuration"),
                    "{error}"
                );
            }
        }
    }
}

// An endpoint's new requests take three quarters of its UDP write limits.
// With a backend, or on a port, a share without a write or smaller than the
// backend's largest payload would refuse such requests as busy however idle
// the endpoint was, so bind refuses it. An endpoint with a socket of its own
// keeps zero limits valid, as a way to refuse its writes.
#[tokio::test]
async fn an_endpoint_s_write_limits_must_hold_a_whole_payload() {
    let (port, _ingress) = intercept(&Wire::default());
    for limits in [
        Limits { count: 0, bytes: 64 * 1024 },
        Limits { count: 16, bytes: 1472 },
    ] {
        let own = Endpoint::builder()
            .udp_io(Wire::default())
            .udp_write_limits(limits)
            .bind();
        let shared =
            Endpoint::builder().udp_write_limits(limits).bind_on(&port);

        assert!(own.unwrap_err().is_invalid_config(), "{limits:?}");
        assert!(shared.unwrap_err().is_invalid_config(), "{limits:?}");
    }

    let fits = Limits { count: 1, bytes: 1963 };
    Endpoint::builder()
        .udp_io(Wire::default())
        .udp_write_limits(fits)
        .bind()
        .unwrap();
    Endpoint::builder().udp_write_limits(fits).bind_on(&port).unwrap();
    Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .udp_write_limits(Limits { count: 0, bytes: 0 })
        .bind()
        .unwrap();
}

// Endpoints whose writes find the port's limits full wait, and go out as
// room frees up, without losing a write or an outcome.
#[tokio::test]
async fn endpoints_wait_for_room_in_the_port_s_limits() {
    let wire = Wire::default();
    let (port, _ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .write_limits(Limits { count: 1, bytes: 64 * 1024 })
        .intercept()
        .unwrap();
    let (a, _a_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let (b, _b_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    wire.writes(Writes::Delay);

    let from_a = send_options(&a, "a");
    wire.sent(1).await;
    let from_b = send_options(&b, "b");
    sleep(Duration::from_millis(20)).await;
    assert_eq!(wire.count(), 1);
    wire.finish(Ok(()));
    wire.sent(2).await;
    wire.finish(Ok(()));

    assert!(from_a.await.unwrap().is_ok());
    assert!(from_b.await.unwrap().is_ok());
}

// A raw send refused for room takes none of it, not even for a moment. An
// endpoint waiting while one is refused goes out as soon as the write ahead
// of it ends, with no other traffic to wake it.
#[tokio::test]
async fn a_refused_raw_send_does_not_hold_back_a_waiting_endpoint() {
    let wire = Wire::default();
    let (port, _ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .write_limits(Limits { count: 1, bytes: 2000 })
        .intercept()
        .unwrap();
    let (a, _a_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let (b, _b_incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    // Within the three quarters that raw sends may take, but not beside the
    // endpoint's write.
    let large = Bytes::from(vec![b'x'; 1200]);

    wire.writes(Writes::Delay);
    let from_a = send_options(&a, "a");
    wire.sent(1).await;
    let refused = port.send_bytes(large.clone(), &upstream);
    assert!(refused.unwrap_err().is_busy());
    let from_b = send_options(&b, "b");
    sleep(Duration::from_millis(20)).await;
    let refused = port.send_bytes(large, &upstream);
    assert!(refused.unwrap_err().is_busy());
    assert_eq!(wire.count(), 1);

    wire.finish(Ok(()));
    wire.sent(2).await;
    wire.finish(Ok(()));
    assert!(from_a.await.unwrap().is_ok());
    assert!(from_b.await.unwrap().is_ok());
}

// The same with endpoints on several threads at once, where a waiter and a
// release race. Every write still goes out and reports back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoints_on_several_threads_share_the_port_s_limits() {
    let wire = Wire::default();
    let (port, _ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .write_limits(Limits { count: 2, bytes: 64 * 1024 })
        .intercept()
        .unwrap();
    let mut endpoints = Vec::new();
    for _ in 0..4 {
        endpoints.push(Endpoint::builder().bind_on(&port).unwrap());
    }

    let mut sends = Vec::new();
    for (endpoint, _incoming, _) in &endpoints {
        for _ in 0..25 {
            sends.push(send_options(endpoint, "busy"));
        }
    }
    for send in sends {
        let sent = timeout(Duration::from_secs(10), send).await.unwrap();
        sent.unwrap().unwrap();
    }

    assert_eq!(wire.count(), 100);
}

// Raw sends take at most three quarters of the port's write limits, so that
// a busy forwarder leaves endpoints room for their own writes.
#[tokio::test]
async fn raw_sends_leave_endpoints_room() {
    let wire = Wire::default();
    let (port, _ingress) = DatagramPort::builder()
        .udp_io(wire.clone())
        .write_limits(Limits { count: 4, bytes: 64 * 1024 })
        .intercept()
        .unwrap();
    let (endpoint, _incoming, _) = Endpoint::builder().bind_on(&port).unwrap();
    let upstream = upstream(&port).await;
    wire.writes(Writes::Delay);

    let raw: Vec<_> = (0..3)
        .map(|_| port.send_bytes(Bytes::from_static(b"raw"), &upstream))
        .collect::<Result<_, _>>()
        .unwrap();
    let refused = port.send_bytes(Bytes::from_static(b"raw"), &upstream);
    let from_endpoint = send_options(&endpoint, "room");

    assert!(refused.unwrap_err().is_busy());
    wire.sent(4).await;
    for _ in 0..4 {
        wire.finish(Ok(()));
    }
    assert!(from_endpoint.await.unwrap().is_ok());
    for write in raw {
        write.await.unwrap();
    }
}
