/*!
Admission, progress and terminal outcome of operations.

An operation is something the application asks of the UA, such as accepting an
incoming INVITE. The contracts below are the ones the public handles are to
build on.

# Admission

Submitting a command is synchronous and bounded. It either admits the command
and returns its [`OperationId`], or refuses it with a [`SubmitError`] that
hands the whole command back. A refused command changes no state and has no
wire effect, so what it carried, such as the authority to decide an incoming
INVITE, is still the caller's. Admission is the point the operation takes
effect. Nothing that happens to the waiter afterwards withdraws it.

# Progress

An admitted operation passes through [`Stage`]s that keep apart what is often
called "sent": the UA accepting the command, the core accepting the message,
the local write finishing, and the peer answering. Each later stage says more
than the one before, and none of them says the peer received anything unless
it answered. Notifications to the application are a separate channel and are
not stages.

# Terminal outcome

An operation ends with one outcome, set once. A later attempt to set another is
ignored, so a race between, say, an accept and a CANCEL cannot report both. The
outcome does not travel through the notification queue, where an overflow could
lose it. It stays in the operation's record until its waiter takes it. If the
waiter is gone, the record stays for a fixed time after the outcome so that a
snapshot can still read it, and is then reclaimed. The table has a fixed size,
so this retention is bounded too.

# Dropping handles

What dropping each application-side handle means:

* An operation waiter: nothing happens to the operation. It runs to its
  outcome, and the outcome is kept for a while.
* The decision authority of an incoming INVITE that has no final yet: the UA
  sends the final of its abandonment policy, unless a CANCEL or a final got
  there first. Drop only sets a flag reserved when the INVITE arrived. It sends
  nothing itself, and a full notification queue cannot lose the flag. The
  model does not do this yet. See `Authority` in the model.
* A session or attempt handle: neither BYE nor CANCEL. The protocol work
  goes on, including the ACK of every 2xx.
* The event receiver: notifications stop. Protocol work does not depend on
  them.
* The driver: a forced stop, not a graceful shutdown.
* A shutdown future: the shutdown it started goes on.
*/

use std::time::{Duration, Instant};

use crate::{
    error::Error,
    invite::UsageKey,
    slot::{Key, Slots},
};

/// The address of an operation's record. It goes stale when the record is
/// reclaimed, so a late result for an old operation finds nothing.
pub(crate) type OperationId = Key<Record>;

/// How far an operation has got, each stage implying the ones before.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Stage {
    /// The UA admitted the command.
    #[default]
    Admitted,
    /// The core accepted the message, such as a final response through its
    /// responder.
    Committed,
    /// The local transport finished writing it.
    Written,
    /// The peer responded.
    Answered,
}

/// What an operation produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Completion {
    /// An INVITE usage was established.
    Session(UsageKey),
}

pub(crate) type Outcome = Result<Completion, Error>;

/// Whether someone still waits for the outcome.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Waiter {
    #[default]
    Attached,
    Dropped,
}

#[derive(Debug, Default)]
pub(crate) struct Record {
    stage: Stage,
    outcome: Option<Outcome>,
    waiter: Waiter,
    /// When the record may be reclaimed. Set once the outcome is in and the
    /// waiter is gone.
    expires: Option<Instant>,
}

/// What a snapshot of an operation shows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Snapshot {
    pub(crate) stage: Stage,
    pub(crate) outcome: Option<Outcome>,
}

/// A command the UA did not admit, handed back unchanged.
#[derive(Debug)]
pub(crate) struct SubmitError<C> {
    pub(crate) error: Error,
    pub(crate) command: C,
}

/// The records of admitted operations.
#[derive(Debug)]
pub(crate) struct Operations {
    records: Slots<Record>,
    /// How long an outcome nobody waits for is kept.
    retention: Duration,
}

impl Operations {
    pub(crate) fn new(limit: usize, retention: Duration) -> Operations {
        Operations { records: Slots::new(limit), retention }
    }

    /// Opens a record for a command being admitted, or returns `None` when
    /// the table is full.
    pub(crate) fn admit(&mut self) -> Option<OperationId> {
        self.records.insert(Record::default()).ok()
    }

    /// Moves the operation to `stage`. Stages never go back.
    pub(crate) fn advance(&mut self, id: OperationId, stage: Stage) {
        if let Some(record) = self.records.get_mut(id) {
            record.stage = record.stage.max(stage);
        }
    }

    /// Sets the outcome, unless one is already set. Returns whether this
    /// call set it.
    pub(crate) fn complete(
        &mut self,
        id: OperationId,
        outcome: Outcome,
        now: Instant,
    ) -> bool {
        let Some(record) = self.records.get_mut(id) else {
            return false;
        };
        if record.outcome.is_some() {
            return false;
        }

        record.outcome = Some(outcome);
        if record.waiter == Waiter::Dropped {
            record.expires = Some(now + self.retention);
        }
        true
    }

    /// Records that nobody waits for the outcome any more. The operation
    /// itself goes on.
    pub(crate) fn drop_waiter(&mut self, id: OperationId, now: Instant) {
        let Some(record) = self.records.get_mut(id) else {
            return;
        };

        record.waiter = Waiter::Dropped;
        if record.outcome.is_some() {
            record.expires = Some(now + self.retention);
        }
    }

    /// Hands the outcome to its waiter and reclaims the record, or returns
    /// `None` while the operation runs.
    pub(crate) fn take(&mut self, id: OperationId) -> Option<Outcome> {
        let outcome = self.records.get(id)?.outcome?;

        self.records.remove(id);
        Some(outcome)
    }

    pub(crate) fn snapshot(&self, id: OperationId) -> Option<Snapshot> {
        let record = self.records.get(id)?;
        Some(Snapshot { stage: record.stage, outcome: record.outcome })
    }

    /// Reclaims the records whose outcome has been kept long enough.
    pub(crate) fn expire(&mut self, now: Instant) {
        let expired: Vec<OperationId> = self
            .records
            .iter()
            .filter(|(_, record)| record.expires.is_some_and(|at| at <= now))
            .map(|(id, _)| id)
            .collect();

        for id in expired {
            self.records.remove(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RETENTION: Duration = Duration::from_secs(32);

    #[test]
    fn the_first_outcome_sticks() {
        let mut operations = Operations::new(1, RETENTION);
        let now = Instant::now();
        let id = operations.admit().unwrap();

        assert!(operations.complete(id, Err(Error::AlreadyFinalized), now));
        assert!(!operations.complete(id, Err(Error::Busy), now));

        assert_eq!(operations.take(id), Some(Err(Error::AlreadyFinalized)));
        assert_eq!(operations.snapshot(id), None);
    }

    #[test]
    fn stages_only_move_forward() {
        let mut operations = Operations::new(1, RETENTION);
        let id = operations.admit().unwrap();

        for stage in [Stage::Committed, Stage::Answered, Stage::Written] {
            operations.advance(id, stage);
        }

        let snapshot = operations.snapshot(id).unwrap();
        assert_eq!(snapshot.stage, Stage::Answered);
        assert_eq!(snapshot.outcome, None);
    }

    #[test]
    fn an_unwatched_outcome_is_kept_for_the_retention_time() {
        let mut operations = Operations::new(1, RETENTION);
        let start = Instant::now();
        let id = operations.admit().unwrap();

        operations.drop_waiter(id, start);
        operations.expire(start + 2 * RETENTION);
        assert!(operations.snapshot(id).is_some(), "still running");

        let done = start + Duration::from_secs(1);
        operations.complete(id, Err(Error::TransportFailure), done);

        operations.expire(done + RETENTION - Duration::from_millis(1));
        assert!(operations.snapshot(id).is_some());
        operations.expire(done + RETENTION);
        assert_eq!(operations.snapshot(id), None);
        assert!(operations.admit().is_some(), "the slot is free again");
    }

    #[test]
    fn a_running_operation_has_nothing_to_take() {
        let mut operations = Operations::new(1, RETENTION);
        let id = operations.admit().unwrap();

        assert_eq!(operations.take(id), None);
        assert!(operations.snapshot(id).is_some());
        assert!(operations.admit().is_none(), "the table is full");
    }
}
