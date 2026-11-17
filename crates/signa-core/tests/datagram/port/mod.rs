/*!
Ports that several endpoints share. The application receives each datagram
from the port and delivers it to an endpoint, forwards it unchanged or
discards it, while the port writes for all of them.

* `delivery`: what the application does with each datagram, and a capture
  that only receives.
* `isolation`: the endpoints on one port keep apart.
* `outcome`: each write learns how it ended.
* `limits`: the port's write limits, shared by its endpoints and raw sends.
* `close`: quiescing and closing a port.
* `observe`: a port's observer.
*/

mod close;
mod delivery;
mod isolation;
mod limits;
mod observe;
mod outcome;

use std::time::Duration;

use signa_core::endpoint::{
    PathSelection,
    port::{self, DatagramPort, Ingress, RawPath, ReceivedDatagram},
};
use tokio::{task::yield_now, time::timeout};

use crate::datagram::{LOCAL, PUBLIC, context, wire::Wire};

/// A port on `wire` whose datagrams the test disposes of.
pub(crate) fn intercept(wire: &Wire) -> (DatagramPort, Ingress) {
    DatagramPort::builder().udp_io(wire.clone()).intercept().unwrap()
}

/// The next datagram the port received.
pub(crate) async fn next(ingress: &mut Ingress) -> ReceivedDatagram {
    timeout(Duration::from_secs(2), ingress.recv())
        .await
        .expect("a datagram within two seconds")
        .expect("an open port")
}

/// Waits until the port's counts satisfy `done`.
async fn stats_until(port: &DatagramPort, done: impl Fn(port::Stats) -> bool) {
    timeout(Duration::from_secs(2), async {
        while !done(port.stats()) {
            yield_now().await;
        }
    })
    .await
    .expect("the counts within two seconds");
}

/// A raw path from the wire's address to the public address, along `nic1`.
async fn upstream(port: &DatagramPort) -> RawPath {
    let selection = PathSelection::new(LOCAL, PUBLIC).context(context("nic1"));
    port.prepare_path(selection).await.unwrap()
}
