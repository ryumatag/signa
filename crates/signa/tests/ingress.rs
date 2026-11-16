//! An application outside signa-core that classifies the datagrams of a
//! shared port through the facade's paths alone: requests to an endpoint,
//! responses forwarded unchanged, the rest discarded. Its backend is a pipe
//! of its own, as an adapter for a NIC would be.

use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::Bytes;
use signa::{
    Message,
    endpoint::{
        Endpoint, IncomingEvent, PathSelection, ShutdownOutcome,
        port::{DatagramPort, EndpointIngress, RawPath, ReceivedDatagram},
    },
    transport::datagram::{
        Capabilities, Datagram, DatagramIo, DatagramWrite, RecvError, Submit,
        TransportContext, WriteId, WriteOutcome,
    },
};
use tokio::time::timeout;

const LOCAL: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)),
    5060,
);
const PEER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 20)),
    5060,
);
const UPSTREAM: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7)),
    5060,
);

#[derive(Default)]
struct Pipe {
    inbound: VecDeque<Datagram>,
    recv: Option<Waker>,
    outbound: Vec<(SocketAddr, Bytes)>,
    done: VecDeque<WriteId>,
}

/// A backend whose datagrams the test puts in and takes out.
#[derive(Clone, Default)]
struct Backend(Arc<Mutex<Pipe>>);

impl Backend {
    fn put(&self, payload: &'static str) {
        let mut pipe = self.0.lock().unwrap();
        pipe.inbound.push_back(Datagram::new(
            Bytes::from_static(payload.as_bytes()),
            PEER,
            LOCAL,
        ));
        if let Some(waker) = pipe.recv.take() {
            waker.wake();
        }
    }

    fn written(&self) -> Vec<(SocketAddr, Bytes)> {
        self.0.lock().unwrap().outbound.clone()
    }
}

impl DatagramIo for Backend {
    fn local_addr(&self) -> SocketAddr {
        LOCAL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::new(1472)
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Datagram, RecvError>> {
        let mut pipe = self.0.lock().unwrap();
        match pipe.inbound.pop_front() {
            Some(datagram) => Poll::Ready(Ok(datagram)),
            None => {
                pipe.recv = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn poll_submit(
        &mut self,
        _cx: &mut Context<'_>,
        write: DatagramWrite,
    ) -> Submit {
        let mut pipe = self.0.lock().unwrap();
        pipe.done.push_back(write.id());
        pipe.outbound.push((write.destination(), write.into_payload()));
        Submit::Accepted
    }

    fn poll_complete(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<(WriteId, WriteOutcome)> {
        match self.0.lock().unwrap().done.pop_front() {
            Some(id) => Poll::Ready((id, WriteOutcome::Written)),
            None => Poll::Pending,
        }
    }

    fn check_path(
        &mut self,
        source: SocketAddr,
        _destination: SocketAddr,
        _context: &TransportContext,
    ) -> io::Result<()> {
        if source == LOCAL {
            Ok(())
        } else {
            Err(io::ErrorKind::AddrNotAvailable.into())
        }
    }

    fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}

const INVITE: &str = "INVITE sip:bob@192.0.2.10 SIP/2.0\r\n\
    Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bKfacade;rport\r\n\
    Max-Forwards: 70\r\n\
    From: <sip:alice@192.0.2.20>;tag=alice\r\n\
    To: <sip:bob@192.0.2.10>\r\n\
    Call-ID: facade\r\n\
    CSeq: 1 INVITE\r\n\
    Contact: <sip:alice@192.0.2.20>\r\n\
    Content-Length: 0\r\n\r\n";

const RESPONSE: &str = "SIP/2.0 180 Ringing\r\n\
    v: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bKup\r\n\
    f: <sip:carol@198.51.100.7>;tag=c\r\n\
    t: <sip:dave@192.0.2.20>;tag=d\r\n\
    i: upstream\r\n\
    CSeq: 1 INVITE\r\n\
    l: 0\r\n\r\n";

/// The decision the application makes about each datagram.
async fn classify(
    datagram: ReceivedDatagram,
    to_endpoint: &EndpointIngress,
    upstream: &RawPath,
) {
    match datagram.parse() {
        Ok(Message::Request(_)) => datagram.try_deliver(to_endpoint).unwrap(),
        Ok(Message::Response(_)) => {
            datagram.try_forward(upstream).unwrap().await.unwrap();
        }
        Err(_) => datagram.discard(),
    }
}

#[tokio::test]
async fn an_application_classifies_a_shared_port_through_the_facade() {
    let backend = Backend::default();
    let (port, mut ingress) =
        DatagramPort::builder().udp_io(backend.clone()).intercept().unwrap();
    let (endpoint, mut incoming) =
        Endpoint::builder().port(&port).bind().unwrap();
    let to_endpoint = endpoint.ingress().unwrap();
    let upstream =
        port.prepare_path(PathSelection::new(LOCAL, UPSTREAM)).await.unwrap();

    backend.put(INVITE);
    backend.put(RESPONSE);
    backend.put("not SIP at all");
    for _ in 0..3 {
        let datagram = timeout(Duration::from_secs(2), ingress.recv())
            .await
            .unwrap()
            .unwrap();
        classify(datagram, &to_endpoint, &upstream).await;
    }

    let event = timeout(Duration::from_secs(2), incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, IncomingEvent::Request(_)));
    // The endpoint sent its 100 Trying to the INVITE's source, and the
    // response went upstream as it came.
    let written = backend.written();
    assert!(
        written.contains(&(UPSTREAM, Bytes::from_static(RESPONSE.as_bytes())))
    );
    assert!(
        written.iter().any(|(to, payload)| *to == PEER
            && payload.starts_with(b"SIP/2.0 100 "))
    );
    let stats = port.stats();
    assert_eq!((stats.delivered, stats.forwarded, stats.discarded), (1, 1, 1));

    drop(event);
    port.quiesce();
    endpoint.shutdown(Duration::from_millis(10)).await;
    assert_eq!(
        port.close(Duration::from_secs(1)).await,
        ShutdownOutcome::Drained
    );
}
