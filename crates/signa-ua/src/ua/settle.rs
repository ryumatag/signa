/*!
Settlement: when every piece of protocol work the UA did for a session, an
INVITE it sent or an INVITE it received has ended.

A session ends when its BYE goes or comes, but its work goes on after that:
the BYE's transaction, a 2xx that still needs its ACK, a re-INVITE that has
no final response yet. An application that frees what a call holds, such as
the routing of its packets, waits for that work rather than for the end. The
driver tracks it here, apart from the events, so that a full event queue
loses none of it.

Each [`Owner`] the driver tracks has holds, one for each thing still under
way:

* the model's records, until it releases the owner,
* each job and watcher the driver runs for it, from the moment it is queued,
  and each answer it waits for from the [`Negotiate`],
* each transaction of signa-core's it started or took for it, until that
  transaction settles,
* each owner it waits for, until that one settles.

It settles once it holds nothing. A session waits for the attempt or the
incoming INVITE that formed it, since a fork's 2xx and the copies of a 2xx
come through their transactions. It takes the counts of an incoming INVITE
it was accepted from, whose writes were all its own, but only whether an
attempt drained, whose writes were shared among its forks.

[`Negotiate`]: super::Negotiate
*/

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    sync::{Arc, OnceLock},
};

use signa_core::endpoint::{
    Settled as CoreSettled, Settlement as CoreSettlement,
};
use tokio::{
    sync::Notify,
    task::{self, JoinSet},
};

use crate::{
    invite::{ExchangeKey, UsageKey},
    model::Owner,
};

/// How the work of a session, an INVITE this UA sent, or an INVITE it
/// received, ended, as [`Settlement`] reports it.
///
/// Its counts are of the local writes of that work, as signa-core counts
/// them: the requests and responses of each transaction, their
/// retransmissions included, and the ACKs and copies of a 2xx the UA sends
/// outside a transaction. None of them says that the peer received
/// anything.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Settled {
    drained: bool,
    written: u32,
    not_written: u32,
    unknown: u32,
}

impl Settled {
    /// Nothing was written, and nothing stopped the work.
    const EMPTY: Settled =
        Settled { drained: true, written: 0, not_written: 0, unknown: 0 };

    /// The work stopped, with nothing known of its writes.
    pub(super) const STOPPED: Settled =
        Settled { drained: false, ..Settled::EMPTY };

    /// Whether all of the work ended before the UA or its endpoint stopped.
    ///
    /// It is `false` when a shutdown's deadline came first, the endpoint
    /// stopped on its own, or the [`UaDriver`] was dropped, and the UA or
    /// the endpoint let go of work that had not ended. It says nothing about
    /// how the work went. A BYE that got a 481, or a transaction that timed
    /// out, ended all the same.
    ///
    /// [`UaDriver`]: super::UaDriver
    pub fn is_drained(&self) -> bool {
        self.drained
    }

    /// Writes that went out whole, which is not receipt by the peer.
    pub fn written(&self) -> u32 {
        self.written
    }

    /// Writes that did not go out: the transport refused or failed them, or
    /// a TCP connection they needed could not be opened. A TCP write can
    /// fail after a part of it went out.
    pub fn not_written(&self) -> u32 {
        self.not_written
    }

    /// Writes whose outcome is not known: a UDP backend took them and could
    /// not account for them, the UA gave up waiting for them, or the endpoint
    /// gave up on them as it stopped. They may have gone out.
    pub fn outcome_unknown(&self) -> u32 {
        self.unknown
    }

    /// Adds what `other` counted, and whether it drained.
    fn merge(&mut self, other: Settled) {
        self.drained &= other.drained;
        self.written = self.written.saturating_add(other.written);
        self.not_written = self.not_written.saturating_add(other.not_written);
        self.unknown = self.unknown.saturating_add(other.unknown);
    }
}

impl From<CoreSettled> for Settled {
    fn from(settled: CoreSettled) -> Settled {
        Settled {
            drained: settled.is_drained(),
            written: settled.written(),
            not_written: settled.not_written(),
            unknown: settled
                .outcome_unknown()
                .saturating_add(settled.abandoned()),
        }
    }
}

/// How one write the UA made outside a transaction ended: an ACK, or a copy
/// of a 2xx.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Write {
    Written,
    NotWritten,
    Unknown,
}

/// Waits for the work of a session, an INVITE this UA sent, or an INVITE it
/// received, to end.
///
/// [`Session::settlement`], [`InviteAttempt::settlement`] and
/// [`IncomingInvite::settlement`] return one. It resolves once, with the
/// same [`Settled`] for every clone, and keeps it for as long as any clone
/// lives, whatever happened to the events. It holds neither the UA nor its
/// work, and dropping it, or its `wait` future, changes nothing. Dropping
/// the [`UaDriver`] resolves it, as work that did not drain.
///
/// It is not signa-core's settlement of one transaction, though it waits
/// for those of every transaction of its work, and adds what the UA does
/// outside them.
///
/// [`UaDriver`]: super::UaDriver
///
/// [`Session::settlement`]: super::Session::settlement
/// [`InviteAttempt::settlement`]: super::InviteAttempt::settlement
/// [`IncomingInvite::settlement`]: super::IncomingInvite::settlement
#[derive(Clone)]
pub struct Settlement {
    slot: Arc<Slot>,
}

impl Settlement {
    /// Returns how the work settled, or `None` while it has not.
    pub fn get(&self) -> Option<Settled> {
        self.slot.settled.get().copied()
    }

    /// Waits until the work settles.
    ///
    /// It is cancellation-safe.
    ///
    /// # Example
    ///
    /// A B2BUA keeps the packet routing of a call until both of its legs
    /// have settled, so that the ACK of a late 2xx and the response to a BYE
    /// still find their way.
    ///
    /// ```no_run
    /// use signa_ua::Session;
    ///
    /// async fn release_when_settled(caller: Session, callee: Session) {
    ///     let (caller, callee) = (caller.settlement(), callee.settlement());
    ///     let (caller, callee) = tokio::join!(caller.wait(), callee.wait());
    ///     if !(caller.is_drained() && callee.is_drained()) {
    ///         eprintln!("the UA stopped before a leg ended");
    ///     }
    ///     // Free the routing of the call's packets here.
    /// }
    /// ```
    #[allow(clippy::manual_async_fn)] // State the Send guarantee.
    pub fn wait(&self) -> impl Future<Output = Settled> + Send + '_ {
        async move {
            loop {
                let notified = self.slot.notify.notified();
                let mut notified = std::pin::pin!(notified);
                // Enabled before the check, so a settlement after it still
                // wakes this waiter.
                notified.as_mut().enable();
                if let Some(settled) = self.get() {
                    return settled;
                }
                notified.await;
            }
        }
    }

    /// A settlement for an owner the driver no longer tracks, which a handle
    /// made then would need. It does not happen, and reports what it can, a
    /// stop with nothing known.
    fn lost() -> Settlement {
        let slot = Arc::new(Slot::default());
        slot.publish(Settled::STOPPED);
        Settlement { slot }
    }
}

impl fmt::Debug for Settlement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Settlement").field(&self.get()).finish()
    }
}

/// Where a settlement is published, which its handles share.
#[derive(Default)]
struct Slot {
    settled: OnceLock<Settled>,
    notify: Notify,
}

impl Slot {
    /// Publishes `settled`, unless it was published before.
    fn publish(&self, settled: Settled) {
        if self.settled.set(settled).is_ok() {
            self.notify.notify_waiters();
        }
    }
}

/// The work of one owner, until it settles.
struct Tracker {
    slot: Arc<Slot>,
    /// What is still under way, as the module documentation lists it.
    holds: usize,
    /// What has ended so far.
    settled: Settled,
    /// The owners that wait for this one, and whether each takes its counts
    /// or only whether it drained.
    dependents: Vec<(Owner, bool)>,
}

impl Drop for Tracker {
    /// A tracker dropped before it settled is one the driver let go of as it
    /// stopped, so its work did not drain. One that settled was published
    /// already, and this changes nothing.
    fn drop(&mut self) {
        let mut settled = self.settled;
        settled.drained = false;
        self.slot.publish(settled);
    }
}

/// The work each owner of the driver still has under way.
#[derive(Default)]
pub(super) struct Trackers {
    trackers: HashMap<Owner, Tracker>,
    /// Wait for the transactions of signa-core's that the owners hold, one
    /// task each, until each settles.
    settlers: JoinSet<CoreSettled>,
    /// The owner each of `settlers` waits for.
    settling: HashMap<task::Id, Owner>,
}

impl Trackers {
    /// Starts to track `owner`, whose records the model holds until it
    /// releases them. That is its first hold.
    ///
    /// An owner is tracked once. Were it tracked again, the old tracker would
    /// go as one that did not drain, rather than share its holds with the
    /// new one.
    pub(super) fn track(&mut self, owner: Owner) {
        let tracker = Tracker {
            slot: Arc::default(),
            holds: 1,
            settled: Settled::EMPTY,
            dependents: Vec::new(),
        };
        let old = self.trackers.insert(owner, tracker);
        debug_assert!(old.is_none(), "{owner:?} tracked twice");
    }

    /// Says whether `owner` is tracked.
    pub(super) fn tracks(&self, owner: Owner) -> bool {
        self.trackers.contains_key(&owner)
    }

    /// Returns the settlement of `owner`, for a handle to carry.
    pub(super) fn settlement(&self, owner: Owner) -> Settlement {
        match self.trackers.get(&owner) {
            Some(tracker) => Settlement { slot: tracker.slot.clone() },
            None => {
                debug_assert!(false, "a handle of {owner:?}, which settled");
                Settlement::lost()
            }
        }
    }

    /// Adds a hold on `owner`, if it is tracked, and returns it to release
    /// later.
    pub(super) fn hold(&mut self, owner: Owner) -> Option<Owner> {
        let tracker = self.trackers.get_mut(&owner)?;
        tracker.holds += 1;
        Some(owner)
    }

    /// Has `dependent` wait for `owner`, if both are tracked. With
    /// `inherit`, it takes the counts of `owner` too.
    pub(super) fn depend(
        &mut self,
        dependent: Owner,
        owner: Owner,
        inherit: bool,
    ) {
        if !self.tracks(dependent) {
            return;
        }
        let Some(tracker) = self.trackers.get_mut(&owner) else {
            return;
        };

        tracker.dependents.push((dependent, inherit));
        self.hold(dependent);
    }

    /// Has `owner`, if any and tracked, hold until the transaction of
    /// `settlement` settles.
    pub(super) fn settle_on(
        &mut self,
        owner: Option<Owner>,
        settlement: CoreSettlement,
    ) {
        let Some(owner) = owner.and_then(|owner| self.hold(owner)) else {
            return;
        };

        let handle =
            self.settlers.spawn(async move { settlement.wait().await });
        self.settling.insert(handle.id(), owner);
    }

    /// Tracks the work of an incoming INVITE, whose transaction is the
    /// exchange's, and has the session of a re-INVITE wait for it.
    pub(super) fn track_exchange(
        &mut self,
        exchange: ExchangeKey,
        usage: Option<UsageKey>,
        settlement: CoreSettlement,
    ) {
        let owner = Owner::Exchange(exchange);
        self.track(owner);
        self.settle_on(Some(owner), settlement);
        if let Some(usage) = usage {
            self.depend(Owner::Usage(usage), owner, true);
        }
    }

    /// Says whether a transaction is waited for.
    pub(super) fn has_settlers(&self) -> bool {
        !self.settlers.is_empty()
    }

    /// Waits for the next transaction to settle. It is cancellation-safe.
    pub(super) async fn next_settled(
        &mut self,
    ) -> Option<Result<(task::Id, CoreSettled), task::JoinError>> {
        self.settlers.join_next_with_id().await
    }

    /// Takes the settlement of a transaction an owner held. One that never
    /// came, as when the task was aborted, did not drain.
    pub(super) fn on_settled(
        &mut self,
        joined: Result<(task::Id, CoreSettled), task::JoinError>,
    ) {
        let (id, settled) = match joined {
            Ok((id, settled)) => (id, Settled::from(settled)),
            Err(error) => (error.id(), Settled::STOPPED),
        };
        if let Some(owner) = self.settling.remove(&id) {
            self.settled(owner, settled);
        }
    }

    /// Counts a write the UA made for `owner` outside a transaction.
    pub(super) fn wrote(&mut self, owner: Owner, write: Write) {
        let Some(tracker) = self.trackers.get_mut(&owner) else {
            return;
        };
        let settled = &mut tracker.settled;
        let count = match write {
            Write::Written => &mut settled.written,
            Write::NotWritten => &mut settled.not_written,
            Write::Unknown => &mut settled.unknown,
        };
        *count = count.saturating_add(1);
    }

    /// Releases a hold on `owner` that a transaction of signa-core's had,
    /// which settled as `settled`.
    fn settled(&mut self, owner: Owner, settled: Settled) {
        if let Some(tracker) = self.trackers.get_mut(&owner) {
            tracker.settled.merge(settled);
        }
        self.release(owner);
    }

    /// Releases a hold on `owner`, which settles once it has none. Those
    /// that wait for it then take what it settled as, and release their
    /// hold on it in turn.
    ///
    /// A tracker leaves the map as its last hold goes, so a release never
    /// finds one with none. A release too many finds no tracker and does
    /// nothing, or takes a hold of another kind early, which the driver's
    /// checks catch.
    pub(super) fn release(&mut self, owner: Owner) {
        self.release_from(owner, None);
    }

    /// Releases a hold on `owner`, which `from` had, if it is an owner that
    /// settled as its `Settled`, with whether `owner` takes its counts.
    ///
    /// Only a session waits for other owners, and nothing waits for a
    /// session, so this recurses once at most.
    fn release_from(&mut self, owner: Owner, from: Option<(Settled, bool)>) {
        let Some(tracker) = self.trackers.get_mut(&owner) else {
            return;
        };
        match from {
            Some((settled, true)) => tracker.settled.merge(settled),
            Some((settled, false)) => {
                tracker.settled.drained &= settled.drained
            }
            None => {}
        }
        tracker.holds -= 1;
        if tracker.holds > 0 {
            return;
        }

        let mut tracker = self.trackers.remove(&owner).expect("found");
        tracker.slot.publish(tracker.settled);
        for (dependent, inherit) in std::mem::take(&mut tracker.dependents) {
            self.release_from(dependent, Some((tracker.settled, inherit)));
        }
    }

    /// Returns each tracked owner with its holds, for the driver's checks.
    #[cfg(debug_assertions)]
    pub(super) fn holds(&self) -> impl Iterator<Item = (Owner, usize)> + '_ {
        self.trackers.iter().map(|(&owner, tracker)| (owner, tracker.holds))
    }

    /// Returns how many holds each owner has on others and on the
    /// transactions it waits for, for the driver's checks.
    #[cfg(debug_assertions)]
    pub(super) fn waits(&self) -> HashMap<Owner, usize> {
        assert_eq!(self.settling.len(), self.settlers.len());
        let mut waits = HashMap::new();
        let dependents = self.trackers.values().flat_map(|tracker| {
            tracker.dependents.iter().map(|&(dependent, _)| dependent)
        });
        for owner in dependents.chain(self.settling.values().copied()) {
            *waits.entry(owner).or_default() += 1;
        }
        waits
    }

    /// Lets go of every owner left, whose work did not drain, as the driver
    /// stops. The caller has joined the transactions it could.
    pub(super) fn clear(&mut self) {
        self.settlers.abort_all();
        self.settling.clear();
        self.trackers.clear();
    }

    pub(super) fn len(&self) -> usize {
        self.trackers.len()
    }
}

#[cfg(test)]
mod tests {
    use quickcheck::QuickCheck;

    use super::*;
    use crate::slot::Key;

    /// An attempt and the session it formed, and an incoming INVITE and the
    /// session it formed, each session waiting for what formed it.
    const ATTEMPT: Owner = Owner::Attempt(Key::of(0));
    const EXCHANGE: Owner = Owner::Exchange(Key::of(0));
    const CALLED: Owner = Owner::Usage(Key::of(0));
    const CALLER: Owner = Owner::Usage(Key::of(1));
    const OWNERS: [Owner; 4] = [ATTEMPT, EXCHANGE, CALLED, CALLER];

    fn formed() -> (Trackers, Vec<Settlement>) {
        let mut trackers = Trackers::default();
        for owner in OWNERS {
            trackers.track(owner);
        }
        trackers.depend(CALLER, ATTEMPT, false);
        trackers.depend(CALLED, EXCHANGE, true);
        let settlements = OWNERS.map(|owner| trackers.settlement(owner));
        (trackers, settlements.to_vec())
    }

    /// Any order of holds, releases, settlements of transactions and writes
    /// settles each owner exactly when its last hold goes and what it waits
    /// for has settled, and never again. A session takes the counts of the
    /// incoming INVITE it waited for, and only whether the attempt drained.
    #[test]
    fn an_owner_settles_with_its_last_hold() {
        fn script(steps: Vec<(u8, u8, u8)>) -> bool {
            let (mut trackers, settlements) = formed();
            // Per owner: holds beyond the model's, whether the model still
            // holds it, and what it settles as by itself.
            let mut extra = [0usize; 4];
            let mut model = [true; 4];
            let mut own = [Settled::EMPTY; 4];
            let mut gone = [false; 4];
            let waits = |i: usize| match i {
                2 => Some((1, true)),
                3 => Some((0, false)),
                _ => None,
            };

            // Then everything is released, in turn. Each step adds a hold
            // at most, and each owner has the model's too.
            let mut steps = steps;
            for _ in 0..steps.len() + 1 {
                steps.extend((0..4).map(|i| (i, 1, 0)));
            }
            for (who, what, how) in steps {
                let i = usize::from(who % 4);
                if gone[i] {
                    continue;
                }
                let owner = OWNERS[i];
                match what % 4 {
                    0 => {
                        trackers.hold(owner);
                        extra[i] += 1;
                    }
                    1 if extra[i] > 0 => {
                        extra[i] -= 1;
                        trackers.release(owner);
                    }
                    1 if model[i] => {
                        model[i] = false;
                        trackers.release(owner);
                    }
                    1 => continue,
                    2 => {
                        let settled = Settled {
                            drained: how & 1 == 0,
                            written: u32::from(how >> 1),
                            not_written: 1,
                            unknown: 0,
                        };
                        trackers.hold(owner);
                        own[i].merge(settled);
                        trackers.settled(owner, settled);
                    }
                    _ => {
                        let write = match how % 3 {
                            0 => Write::Written,
                            1 => Write::NotWritten,
                            _ => Write::Unknown,
                        };
                        trackers.wrote(owner, write);
                        let mut settled = Settled::EMPTY;
                        match write {
                            Write::Written => settled.written = 1,
                            Write::NotWritten => settled.not_written = 1,
                            Write::Unknown => settled.unknown = 1,
                        }
                        own[i].merge(settled);
                    }
                }

                // Settle in order, so that what a session waits for goes
                // first.
                for i in 0..4 {
                    let waiting = waits(i).is_some_and(|(on, _)| !gone[on]);
                    let due =
                        !gone[i] && extra[i] == 0 && !model[i] && !waiting;
                    let published = settlements[i].get();
                    if !due {
                        if published.is_some() != gone[i] {
                            return false;
                        }
                        continue;
                    }
                    let mut expected = own[i];
                    if let Some((on, inherit)) = waits(i) {
                        let other = settlements[on].get().expect("first");
                        if inherit {
                            expected.merge(other);
                        } else {
                            expected.drained &= other.drained;
                        }
                    }
                    if published != Some(expected) {
                        return false;
                    }
                    gone[i] = true;
                }
            }
            gone.iter().all(|&gone| gone) && trackers.len() == 0
        }

        QuickCheck::new()
            .tests(1000)
            .quickcheck(script as fn(Vec<(u8, u8, u8)>) -> bool);
    }

    /// Owners let go of as the driver stops settle as not drained, with what
    /// they counted, and one that settled before keeps what it settled as.
    #[test]
    fn a_stop_settles_what_is_left_undrained() {
        let (mut trackers, settlements) = formed();
        trackers.wrote(CALLED, Write::Written);
        trackers.release(ATTEMPT);

        trackers.clear();

        let settled = |i: usize| settlements[i].get().unwrap();
        assert!(settled(0).is_drained());
        assert!(!settled(1).is_drained() && !settled(2).is_drained());
        assert_eq!(settled(2).written(), 1);
        assert!(!settled(3).is_drained());
    }
}
