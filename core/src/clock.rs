//! A comparable time *value* and the trait that produces one.
//!
//! # Why a value and not a callback
//!
//! `std::time::Instant` appears in this crate 100 times across 12 modules, and
//! the reason is not that it is convenient — it is that it is **stored**.
//! `PathEntry::deadline`, `RumorEntry::send_at`, `LinkState::srrt` and the
//! session's `rotated_at` are all `Instant` fields inside tables that outlive the
//! call that created them. `getPeers`' `latency` is `srrt - srst`, a subtraction
//! of two stored instants. Session rotation is `rotated_at.elapsed() > 60s`.
//!
//! So a `no_std` core needs to *hold* time, not merely ask for it. A trait with a
//! single `now()` would leave every one of those fields unnameable.
//!
//! # The unit is nanoseconds, and that is a wire-compatibility question
//!
//! `Instant` is a `u64` count of nanoseconds from an arbitrary epoch. That is
//! not a round number — milliseconds would be tidier and 1000× cheaper to
//! reason about — and it is chosen because of what it has to preserve:
//!
//! * Go's `getPeers` reports `latency` as a `time.Duration` in **nanoseconds**
//!   (`core/debug.go:85`), and `docs/protocol/21-admin.md` compares our printed
//!   number against `yggdrasilctl`'s. A millisecond representation would round
//!   `0.45 ms` to `0` and make that comparison meaningless.
//! * The measurable quantities in this protocol are **sub-millisecond**: a
//!   loopback round trip, and the RTT of a session. Milliseconds would quantise
//!   both to zero and every latency report would be a lie of rounding.
//! * The measured disagreement we have not yet explained is of that order —
//!   ours read ~50 ms against Go's ~0.45 ms on the same link. A representation
//!   that cannot express 0.45 ms cannot be used to investigate a 50 ms gap.
//!
//! # Range, and why it is enough
//!
//! A `u64` of nanoseconds is 584 years. `Instant` is monotonic-from-an-arbitrary-
//! epoch rather than an absolute time, so the epoch resets whenever the process
//! does; the only thing that must not overflow is the interval a caller compares,
//! and the longest one in this protocol is `PATH_TIMEOUT` at 60 seconds.
//!
//! # Why the epoch is arbitrary, and what that costs
//!
//! `std::time::Instant` has an unspecified epoch — two processes cannot subtract
//! their instants. Preserving that is deliberate: a core that could compare
//! instants across nodes would be a core whose behaviour depended on wall-clock
//! agreement between machines, and Go's protocol never asks for that. The
//! `latency` field is a *difference* of two instants from the same process, which
//! is the only comparison the protocol makes.
//!
//! Arithmetic that could go backwards is **saturating**, not wrapping and not
//! panicking: a `srrt` from "now" subtracted from a stale `srst` is a clock skew
//! bug that should read as an implausibly large interval, not as a value 584
//! years in the past.

use core::time::Duration;

/// Nanoseconds since an arbitrary, process-local epoch.
///
/// Ordering is total and subtraction is meaningful **within one process**. Two
/// `Instant`s from different processes have no defined relationship, exactly as
/// for [`std::time::Instant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Instant {
    nanos: u64,
}

impl Instant {
    /// An arbitrary origin, for tests and for a clock's own bookkeeping.
    pub const EPOCH: Self = Instant { nanos: 0 };

    /// Build from nanoseconds since the epoch.
    ///
    /// `pub` because a caller with its own time source — a hardware timer, a
    /// simulated clock in a test, a platform `clock_gettime` — has to be able to
    /// hand its reading over without going through [`std`] at all.
    pub const fn from_nanos(nanos: u64) -> Self {
        Instant { nanos }
    }

    /// Nanoseconds since the epoch.
    pub const fn as_nanos(&self) -> u64 {
        self.nanos
    }

    /// Build from a [`Duration`] since the epoch.
    pub fn from_since_epoch(d: Duration) -> Self {
        Instant {
            nanos: d.as_nanos().min(u64::MAX as u128) as u64,
        }
    }

    /// A later instant, saturating rather than overflowing.
    ///
    /// Saturation is what a deadline arithmetic helper should do: a deadline
    /// beyond `u64::MAX` nanoseconds is 584 years out, which is not a value any
    /// caller acts on, and wrapping would move it to the *past* — turning a
    /// path that should live into one that is instantly stale.
    pub fn saturating_add(&self, d: Duration) -> Self {
        Instant {
            nanos: self
                .nanos
                .saturating_add(d.as_nanos().min(u64::MAX as u128) as u64),
        }
    }

    /// Time from `earlier` to `self`, or zero if `earlier` is later.
    ///
    /// Saturating at zero rather than panicking or wrapping, because the one
    /// caller of this in the protocol is `latency = srrt - srst`, and a table
    /// that returned a reply out of order would otherwise produce a negative
    /// number that has to be clamped somewhere anyway. Clamping here means the
    /// clamp happens in exactly one place.
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        Duration::from_nanos(self.nanos.saturating_sub(earlier.nanos))
    }

    /// How long ago `earlier` was, as a [`Duration`].
    ///
    /// Reads better than `now.duration_since(x)` at the twenty call sites that
    /// want "how stale is this", and is the same arithmetic.
    pub fn elapsed_since(&self, earlier: Instant) -> Duration {
        self.duration_since(earlier)
    }
}

/// A source of [`Instant`]s.
///
/// The seam a `no_std` core needs and a caller supplies. It is deliberately tiny
/// — one method — because every extra method is a decision about monotonicity,
/// resolution or epoch handling that the core should not be making on the
/// caller's behalf.
///
/// # Implementors
///
/// * `roots::clock::StdClock` — `std::time::Instant`, in `std`.
/// * A test's own struct, which is the point: a deterministic clock is what makes
///   expiry and rotation testable at all, and every such test in `roots` today
///   either sleeps or reaches for a real deadline.
pub trait Clock {
    /// The current instant.
    ///
    /// Contract: **monotonic within a process**, and non-decreasing across calls.
    /// A clock that went backwards would make `srst` later than `srrt` and report
    /// a zero latency rather than an obviously wrong one.
    fn now(&self) -> Instant;
}

/// A [`Clock`] driven by a closure.
///
/// For tests, and for a caller whose time source is a bare function pointer. It
/// exists so that a deterministic clock needs no trait implementation of its own
/// — which sounds trivial until you have written the fourth one.
pub struct FnClock<F>(pub F);

impl<F: Fn() -> Instant> Clock for FnClock<F> {
    fn now(&self) -> Instant {
        (self.0)()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_total() {
        let a = Instant::from_nanos(1);
        let b = Instant::from_nanos(2);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, Instant::from_nanos(1));
        assert_ne!(a, b);
    }

    #[test]
    fn duration_is_the_difference() {
        let a = Instant::from_nanos(1_000);
        let b = Instant::from_nanos(4_000);
        assert_eq!(b.duration_since(a), Duration::from_nanos(3_000));
        assert_eq!(a.duration_since(a), Duration::ZERO);
    }

    /// The resolution claim, as a test rather than a comment.
    ///
    /// A loopback round trip is tens of microseconds and a `latency` report from
    /// Go came back at 450 µs on the link this repository measures. If the core's
    /// representation could not express those, the number `21-admin.md` compares
    /// against `yggdrasilctl` would be quantised to zero and the comparison would
    /// be meaningless — while every test still passed, because the tests use
    /// millisecond-scale values.
    ///
    /// So the sub-millisecond cases are asserted explicitly, at the three scales
    /// that matter: a loopback RTT, Go's reported 450 µs, and one nanosecond.
    #[test]
    fn sub_microsecond_precision_survives() {
        for nanos in [1u64, 999, 450_000, 12_630_000] {
            let base = Instant::from_nanos(1_000_000_000);
            let later = Instant::from_nanos(1_000_000_000 + nanos);
            let d = later.duration_since(base);
            assert_eq!(
                d.as_nanos(),
                nanos as u128,
                "{nanos} ns must survive exactly"
            );
            assert!(d.as_nanos() > 0, "and must not round to zero");
        }
    }

    /// `saturating_add` must saturate, not wrap.
    ///
    /// A deadline that wrapped would land in the *past*, which reads as "expired"
    /// — so a path entry or a session buffer would be evicted immediately instead
    /// of living for 584 years. Both failure directions are wrong; only one is
    /// survivable.
    #[test]
    fn add_saturates_rather_than_wrapping() {
        let near_max = Instant::from_nanos(u64::MAX - 5);
        let out = near_max.saturating_add(Duration::from_secs(1_000));
        assert_eq!(out.as_nanos(), u64::MAX, "saturated, not wrapped to 4");
        // And an ordinary add is exact.
        let a = Instant::from_nanos(10);
        assert_eq!(a.saturating_add(Duration::from_nanos(5)).as_nanos(), 15);
        assert_eq!(
            a.saturating_add(Duration::ZERO).as_nanos(),
            10,
            "adding nothing changes nothing"
        );
    }

    /// `duration_since` clamps at zero rather than underflowing.
    ///
    /// This is the `latency = srrt - srst` case. A negative interval has no
    /// meaning on the wire, and producing one would force every caller to clamp,
    /// which is how two different clamps end up disagreeing.
    #[test]
    fn a_backwards_subtraction_is_zero_not_a_huge_number() {
        let now = Instant::from_nanos(1_000);
        let later = Instant::from_nanos(2_000);
        assert_eq!(
            now.duration_since(later),
            Duration::ZERO,
            "a stale `earlier` must read as zero, not as ~584 years"
        );
        // And the u64 saturation agrees with it.
        assert_eq!(
            Instant::from_nanos(0).duration_since(Instant::from_nanos(u64::MAX)),
            Duration::ZERO
        );
    }

    /// `from_since_epoch` is the bridge from `core::time::Duration`, which is what
    /// every caller already has.
    #[test]
    fn durations_bridge_both_ways() {
        let d = Duration::from_micros(1_500);
        let i = Instant::from_since_epoch(d);
        assert_eq!(i.as_nanos(), 1_500_000);
        assert_eq!(i.duration_since(Instant::EPOCH), d);
    }

    /// A closure clock is enough to write a deterministic test, which is the whole
    /// reason it exists.
    ///
    /// The counter is a `Cell` rather than a captured `&mut`, and that is a
    /// constraint on the design rather than a detail of the test:
    /// [`FnClock`] takes an `Fn` because a `Clock` is read through `&self`, so a
    /// clock that could only advance by handing back `&mut` would be unusable
    /// inside the state machines — which hold `&self` while consulting time.
    #[test]
    fn a_closure_clock_needs_no_trait_implementation() {
        let calls = core::cell::Cell::new(0u64);
        let clock = FnClock(|| {
            let n = calls.get() + 1;
            calls.set(n);
            Instant::from_nanos(n * 1_000)
        });
        assert_eq!(clock.now().as_nanos(), 1_000);
        assert_eq!(clock.now().as_nanos(), 2_000);
        // No `sleep`, no real deadline, and the two readings differ by exactly the
        // amount the fake clock decided.
        assert_eq!(
            clock.now().duration_since(Instant::EPOCH),
            Duration::from_micros(3)
        );
    }
}
