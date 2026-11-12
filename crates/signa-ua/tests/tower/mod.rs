/*!
An external Tower adapter for the UA's decisions, and what it shows about
the line between a Tower service and SIP.

`adapter` holds the adapter, and the other modules its tests. They check the
policy the adapter documents, and that the UA keeps every rule of SIP apart
from the service:

* `readiness`: the service is polled ready and called on one instance, and a
  readiness error is a policy of the adapter, not a fault of the UA.
* `lifetime`: the end of a handler, its timeout and its panic are not the
  final response, the ACK, the end of a dialog or a CANCEL (RFC 3261
  sections 9.1, 13.3.1.4 and 15).
* `bounds`: a handler limit that is full holds up no ACK, CANCEL, BYE or
  retransmission of a 2xx, and new INVITEs meet the UA's own limits.
* `shutdown`: the UA's shutdown waits for the decisions the handlers hold,
  and the adapter's handlers end with the UA.

A retry middleware cannot replay an INVITE, since `IncomingInvite` has no
`Clone`. A `compile_fail` doctest beside it in the crate shows that.
*/

mod adapter;
mod bounds;
mod lifetime;
mod readiness;
mod shutdown;

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use signa_ua::{Event, IncomingInvite, ShutdownMode, Ua, UaHandle};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::timeout,
};
use tower::Service;

use crate::support::{WAIT, events::report_within};

use self::adapter::Served;

/// A UA whose driver and adapter run as tasks of their own.
struct Serving {
    handle: UaHandle,
    /// The events other than INVITEs, as the adapter passes them on.
    notifications: mpsc::UnboundedReceiver<Event>,
    driver: JoinHandle<()>,
    adapter: JoinHandle<Served>,
}

impl Serving {
    /// Spawns the driver of `ua`, and an adapter that hands its INVITEs to
    /// `service` until the driver returns.
    fn start<S>(ua: Ua, service: S) -> Serving
    where
        S: Service<IncomingInvite, Response = ()> + Send + 'static,
        S::Future: Send + 'static,
        S::Error: std::fmt::Debug + Send + 'static,
    {
        let Ua { handle, events, driver } = ua;
        // The sender goes with the driver's task, also if it panics, so the
        // receiver resolves once the driver has returned.
        let (returned, stopped) = oneshot::channel::<()>();
        let driver = tokio::spawn(async move {
            driver.await;
            drop(returned);
        });
        let (sender, notifications) = mpsc::unbounded_channel();
        let adapter =
            tokio::spawn(adapter::serve(events, service, stopped, sender));
        Serving { handle, notifications, driver, adapter }
    }

    /// Terminates the UA, and returns what the adapter did once it has
    /// ended with it.
    async fn stop(self) -> Served {
        let shutdown = self
            .handle
            .shutdown(ShutdownMode::Terminate, Duration::from_secs(3));
        report_within(shutdown, Duration::from_secs(5)).await;
        timeout(WAIT, self.adapter)
            .await
            .expect("the adapter ends with its UA")
            .unwrap()
    }

    /// Receives notifications until `pick` takes one.
    async fn notified<T>(
        &mut self,
        mut pick: impl FnMut(Event) -> Option<T>,
    ) -> T {
        loop {
            let next = timeout(WAIT, self.notifications.recv())
                .await
                .expect("a notification in time")
                .expect("an adapter still running");
            if let Some(found) = pick(next) {
                return found;
            }
        }
    }
}

/// Counts the handlers running at once, and the most there were.
#[derive(Clone, Default)]
struct Running {
    now: Arc<AtomicUsize>,
    most: Arc<AtomicUsize>,
}

impl Running {
    /// Counts a handler until the guard drops, as it does when the handler
    /// ends, is dropped or panics.
    fn enter(&self) -> Entered {
        let now = self.now.fetch_add(1, Ordering::SeqCst) + 1;
        self.most.fetch_max(now, Ordering::SeqCst);
        Entered(self.clone())
    }

    fn now(&self) -> usize {
        self.now.load(Ordering::SeqCst)
    }

    fn most(&self) -> usize {
        self.most.load(Ordering::SeqCst)
    }
}

struct Entered(Running);

impl Drop for Entered {
    fn drop(&mut self) {
        self.0.now.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Holds handlers back until the test opens it.
#[derive(Clone)]
struct Gate(watch::Sender<bool>);

impl Gate {
    fn new() -> Gate {
        Gate(watch::Sender::new(false))
    }

    fn open(&self) {
        self.0.send_replace(true);
    }

    async fn passed(&self) {
        let mut open = self.0.subscribe();
        open.wait_for(|open| *open).await.expect("the gate is kept");
    }

    /// Waits until a handler waits at the gate, and so holds its INVITE.
    /// The 100 Trying does not say that much, since signa-core sends it
    /// before the UA takes the INVITE, and a shutdown that reaches the UA
    /// first answers the INVITE with a 503 without handing it on.
    async fn reached(&self) {
        timeout(WAIT, async {
            while self.0.receiver_count() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("a handler reaches the gate");
    }
}
