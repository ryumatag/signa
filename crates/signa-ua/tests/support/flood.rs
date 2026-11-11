/*!
A flood of requests from a peer, and the lock that keeps two floods apart.
*/

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::sync::Notify;

use crate::support::{message::invite_over, peer::Wire};

/// Taken by each test that floods a UA for its whole run, so that two floods
/// do not run at once and the load of each is its own.
pub(crate) static FLOODING: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

/// Sends ACKs that match no dialog and new INVITEs to the UA, 2,000 a
/// second, from a connection of its own, until `stop`. Returns how many
/// messages went.
///
/// The UA answers each INVITE with a 503, which the flood never
/// acknowledges, so signa-core keeps its transaction for Timer H. At this
/// rate that fills less than its transaction table. A flood that fills it
/// has signa-core refuse every new request with a 503, a BYE in a dialog
/// included, before the UA sees any.
pub(crate) fn flood(
    transport: &'static str,
    udp: SocketAddr,
    tcp: SocketAddr,
    stop: Arc<Notify>,
) -> tokio::task::JoinHandle<usize> {
    tokio::spawn(async move {
        let mut wire = Wire::connect(transport, udp, tcp).await;
        let from = wire.address();
        let mut sent = 0;
        let stopped = stop.notified();
        tokio::pin!(stopped);
        loop {
            let message = if sent % 4 == 3 {
                invite_over(transport, from, &format!("flood-{sent}"))
            } else {
                format!(
                    "ACK sip:ua@127.0.0.1 SIP/2.0
Via: SIP/2.0/{transport} {from};branch=z9hG4bK-junk-{sent}
Max-Forwards: 70
To: <sip:ua@127.0.0.1>;tag=junk
From: <sip:flood@{from}>;tag=flood-{sent}
Call-ID: junk-{sent}
CSeq: 1 ACK
Content-Length: 0

"
                )
            };
            tokio::select! {
                () = &mut stopped => return sent,
                () = wire.send(&message) => sent += 1,
            }
            if sent % 50 == 0 {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    })
}
