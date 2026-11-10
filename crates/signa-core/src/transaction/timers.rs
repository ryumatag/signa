use std::{
    fmt,
    time::{Duration, Instant},
};

/// Validated SIP transaction timers.
///
/// Defaults follow [RFC 3261 section 17] and [RFC 6026]. Timer D is an
/// absolute minimum of 32 seconds on UDP, independent of the local T1.
/// Reliable transports use zero for D, I, J, and K in their machines.
///
/// [RFC 3261 section 17]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17
/// [RFC 6026]: https://www.rfc-editor.org/rfc/rfc6026.html#section-8.4
///
/// ```
/// use std::time::Duration;
/// use signa_core::transaction::Timers;
///
/// let timers = Timers::builder().t1(Duration::from_millis(200)).build()?;
/// assert_eq!(timers.t1(), Duration::from_millis(200));
/// assert_eq!(timers.d(), Duration::from_secs(32));
/// # Ok::<(), signa_core::transaction::InvalidTimers>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timers {
    t1: Duration,
    t2: Duration,
    t4: Duration,
    d: Duration,
}

impl Timers {
    /// Returns the RFC defaults.
    pub const fn new() -> Timers {
        Timers {
            t1: Duration::from_millis(500),
            t2: Duration::from_secs(4),
            t4: Duration::from_secs(5),
            d: Duration::from_secs(32),
        }
    }

    /// Starts with the RFC defaults and validates changes at `build`.
    pub fn builder() -> TimersBuilder {
        TimersBuilder::default()
    }

    /// The round-trip time estimate, 500 ms by default.
    pub fn t1(&self) -> Duration {
        self.t1
    }

    /// The cap on E and G retransmission intervals, 4 s by default.
    pub fn t2(&self) -> Duration {
        self.t2
    }

    /// The network clearance interval, 5 s by default.
    pub fn t4(&self) -> Duration {
        self.t4
    }

    /// Timer D on unreliable transports, at least 32 s.
    pub fn d(&self) -> Duration {
        self.d
    }

    #[cfg(any(feature = "tokio", feature = "__bench", test))]
    pub(super) fn transaction_timeout(&self) -> Duration {
        self.t1 * 64
    }

    /// RFC 4320's deadline for an automatic 100 is the sum of the E
    /// intervals before E reaches T2. Construction checked this arithmetic.
    #[cfg(any(feature = "tokio", feature = "__bench", test))]
    pub(super) fn trying_after(&self) -> Duration {
        trying_after(self.t1, self.t2).expect("validated timer sum")
    }
}

impl Default for Timers {
    fn default() -> Timers {
        Timers::new()
    }
}

/// Builds a [`Timers`] value without exposing unchecked fields.
#[derive(Clone, Debug, Default)]
pub struct TimersBuilder {
    timers: Timers,
}

impl TimersBuilder {
    /// Sets a positive round-trip estimate.
    pub fn t1(mut self, value: Duration) -> TimersBuilder {
        self.timers.t1 = value;
        self
    }

    /// Sets a positive retransmission cap.
    pub fn t2(mut self, value: Duration) -> TimersBuilder {
        self.timers.t2 = value;
        self
    }

    /// Sets a positive network clearance interval.
    pub fn t4(mut self, value: Duration) -> TimersBuilder {
        self.timers.t4 = value;
        self
    }

    /// Sets Timer D for UDP. Values below 32 seconds are rejected.
    pub fn d(mut self, value: Duration) -> TimersBuilder {
        self.timers.d = value;
        self
    }

    /// Checks positive durations, Timer D's minimum, and deadline arithmetic.
    ///
    /// Returns an error if a derived duration overflows or cannot be added
    /// to this platform's current monotonic clock. T2 may be below T1.
    pub fn build(self) -> Result<Timers, InvalidTimers> {
        let t = self.timers;
        let now = Instant::now();
        for (name, value) in
            [("T1", t.t1), ("T2", t.t2), ("T4", t.t4), ("D", t.d)]
        {
            if value.is_zero() {
                return Err(InvalidTimers {
                    field: name,
                    reason: "must be positive",
                });
            }
            if now.checked_add(value).is_none() {
                return Err(InvalidTimers {
                    field: name,
                    reason: "exceeds the monotonic clock range",
                });
            }
        }
        if t.d < Duration::from_secs(32) {
            return Err(InvalidTimers {
                field: "D",
                reason: "must be at least 32 seconds",
            });
        }
        let timeout = t
            .t1
            .checked_mul(64)
            .ok_or(InvalidTimers { field: "T1", reason: "64 T1 overflows" })?;
        let trying = trying_after(t.t1, t.t2).ok_or(InvalidTimers {
            field: "T2",
            reason: "the provisional response deadline overflows",
        })?;
        if now.checked_add(timeout.max(trying)).is_none() {
            return Err(InvalidTimers {
                field: "T1/T2",
                reason: "derived deadline exceeds the monotonic clock range",
            });
        }
        Ok(t)
    }
}

fn trying_after(t1: Duration, t2: Duration) -> Option<Duration> {
    let mut total = Duration::ZERO;
    let mut interval = t1;
    while interval < t2 {
        total = total.checked_add(interval)?;
        interval = interval.saturating_mul(2);
    }
    Some(total)
}

/// Invalid transaction timer configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidTimers {
    field: &'static str,
    reason: &'static str,
}

impl fmt::Display for InvalidTimers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.field, self.reason)
    }
}

impl std::error::Error for InvalidTimers {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_derived_intervals() {
        let t = Timers::builder().build().unwrap();
        assert_eq!(t, Timers::new());
        assert_eq!(t.transaction_timeout(), Duration::from_secs(32));
        assert_eq!(t.trying_after(), Duration::from_millis(3500));
        let t = Timers::builder().t1(Duration::from_secs(4)).build().unwrap();
        assert_eq!(t.trying_after(), Duration::ZERO);
        let t =
            Timers::builder().t2(Duration::from_millis(100)).build().unwrap();
        assert_eq!(t.trying_after(), Duration::ZERO);
    }

    #[test]
    fn invalid_values_cannot_make_a_timer_set() {
        for b in [
            Timers::builder().t1(Duration::ZERO),
            Timers::builder().t2(Duration::ZERO),
            Timers::builder().t4(Duration::ZERO),
            Timers::builder().d(Duration::from_secs(31)),
            Timers::builder().t1(Duration::MAX),
            Timers::builder().t2(Duration::MAX),
            Timers::builder().t4(Duration::MAX),
            Timers::builder().d(Duration::MAX),
            Timers::builder().t1(Duration::from_secs(u64::MAX / 32)),
        ] {
            assert!(b.build().is_err());
        }
        assert!(Timers::builder().t1(Duration::from_nanos(1)).build().is_ok());
        assert!(Timers::builder().d(Duration::from_secs(60)).build().is_ok());
    }
}
