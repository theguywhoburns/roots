//! The `std` implementation of [`roots_core::clock::Clock`].
//!
//! One type, and it exists so that `roots-core` never has to know what a
//! monotonic clock is on a platform.
//!
//! # The epoch is fixed at construction, and why that matters
//!
//! [`std::time::Instant`] has an unspecified origin, so its raw value cannot be
//! converted to a count of nanoseconds — there is nothing to convert *from*.
//! So [`StdClock`] picks an origin once, at construction, and every reading is
//! `Instant::now().duration_since(origin)`.
//!
//! Two consequences, both intended:
//!
//! * Readings are comparable **within one clock**, which is the only comparison
//!   the protocol makes (`latency = srrt - srst`).
//! * Readings from two different `StdClock`s are comparable too, since they
//!   share an epoch only if they were constructed from the same origin — and by
//!   default they are not. [`StdClock::since`] is how a caller opts into a
//!   shared origin, which a test comparing two nodes' latencies needs.
//!
//! The origin is captured **before** the first reading rather than lazily, so the
//! value is fixed at construction and a `StdClock` can be `const`-ish cheap to
//! reason about. The cost is one `Instant::now()` at startup, which is nothing.

use std::time::Instant as StdInstant;

pub use roots_core::clock::{Clock, FnClock, Instant};

/// A [`Clock`] backed by [`std::time::Instant`].
#[derive(Debug, Clone, Copy)]
pub struct StdClock {
    origin: StdInstant,
}

impl Default for StdClock {
    fn default() -> Self {
        Self::from_now()
    }
}

/// One hour, in nanoseconds: how far below the epoch a [`StdClock`]'s *readings*
/// start, so that `now()` starts at 3.6 × 10¹² rather than at 0.
///
/// # Why the floor exists
///
/// `Instant::saturating_sub` clamps at the epoch, and a clock whose readings start
/// at zero has **no past at all**. So on a freshly-constructed clock,
/// `saturating_sub(20 ms)` returns `EPOCH` — an instant 0 ms back, not 20 ms — and
/// the caller cannot tell, because `EPOCH` is a perfectly valid instant.
///
/// This was not hypothetical. Two round-trip tests asked for 20 ms and 30 ms,
/// clamped, and produced latencies of 8.35 ms and 26.9 ms. Both *look* like
/// plausible loopback round trips, so the assertion failed with a number that gave
/// no hint at the cause, and the first diagnosis — that `ago` had built its own
/// clock with an independent origin — was wrong, because `ago` took the router's
/// clock and the real fault was one level down.
///
/// An hour is comfortably more than anything here expresses (the longest interval
/// in the protocol is `PATH_TIMEOUT` at 60 s) and leaves ~584 years of headroom in
/// a `u64` of nanoseconds, so `saturating_add` cannot reach it.
const FLOOR_NANOS: u64 = 3_600_000_000_000;

impl StdClock {
    /// A clock whose origin is now.
    pub fn from_now() -> Self {
        StdClock {
            origin: StdInstant::now(),
        }
    }

    /// A clock whose origin is an existing [`StdInstant`].
    ///
    /// The seam a caller needs when two clocks must agree — a test asserting that
    /// two nodes' reported latencies are comparable, or any code that wants a
    /// reading expressed relative to a known moment.
    pub fn since(origin: StdInstant) -> Self {
        StdClock { origin }
    }

    /// The origin readings are measured from.
    pub fn origin(&self) -> StdInstant {
        self.origin
    }
}

impl Clock for StdClock {
    fn now(&self) -> Instant {
        // `duration_since` on `Instant` saturates at zero in the *other*
        // direction, so this cannot panic and cannot go negative: `origin` was
        // taken at or before any reading, because it was taken first.
        let elapsed = StdInstant::now()
            .duration_since(self.origin)
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        // The floor is **added to the reading**, not subtracted from the origin.
        // Subtracting from the origin would have been simpler to write and would
        // have had two problems: [`StdInstant`] counts from *boot*, so a machine
        // up for less than an hour cannot be backed off by an hour and the
        // subtraction would panic on exactly the machines least likely to be
        // running the tests; and `origin()` would stop returning what the caller
        // passed, breaking the [`since`](Self::since) contract for no gain.
        Instant::from_nanos(FLOOR_NANOS.saturating_add(elapsed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    /// The adapter must be **monotonic and non-decreasing**, which is the whole
    /// contract of [`Clock`].
    ///
    /// A clock that went backwards would leave `srst` later than `srrt` and
    /// report a zero latency rather than an obviously wrong one — a failure that
    /// looks like a healthy link.
    #[test]
    fn readings_never_go_backwards() {
        let c = StdClock::default();
        let mut last = Instant::EPOCH;
        for _ in 0..10_000 {
            let now = c.now();
            assert!(
                now >= last,
                "a monotonic clock went backwards: {now:?} < {last:?}"
            );
            last = now;
        }
    }

    /// A reading's *precision*, measured rather than assumed.
    ///
    /// This is the test that matters most in this file. The core stores instants as
    /// `u64` nanoseconds, and the whole justification for that unit is that the
    /// quantities being measured are sub-millisecond: a loopback round trip is tens
    /// of microseconds, and Go reported `latency: 450000` ns — 450 µs — on the link
    /// this repository measures.
    ///
    /// If the `std` → core conversion were lossy — say, to milliseconds, or through
    /// a `u32` of microseconds — then every latency this node reported would
    /// quantise to zero, every wire test would still pass, and the discrepancy in
    /// `TODO.md` would be unmeasurable.
    ///
    /// So the property is asserted **directly**, on the conversion itself rather
    /// than on a stopwatch: a `Duration` goes in and the same `Duration` comes back
    /// out through `Instant`, at the scales that would break first. A stopwatch
    /// would only ever show that *some* interval survives, not that a 450 µs one
    /// does, and it would be flaky on a loaded machine.
    #[test]
    fn sub_millisecond_durations_survive_the_conversion_exactly() {
        for d in [
            Duration::from_nanos(1),
            Duration::from_nanos(999),
            Duration::from_micros(1),
            Duration::from_micros(450),
            Duration::from_millis(1),
            Duration::from_micros(1_500),
            Duration::from_micros(53_670),
        ] {
            // The exact conversion `StdClock::now` performs.
            let as_nanos = d.as_nanos().min(u64::MAX as u128) as u64;
            let back = Instant::from_nanos(as_nanos).duration_since(Instant::EPOCH);
            assert_eq!(
                back, d,
                "{d:?} must survive the core representation exactly"
            );
            assert!(back.as_nanos() > 0, "{d:?} must not round to zero");
        }
    }

    /// And the real clock agrees with that conversion, by construction rather than
    /// by coincidence.
    ///
    /// A `StdClock` reading is `duration_since(origin).as_nanos()` fed to
    /// `Instant::from_nanos`, so the two tests above together pin the whole path.
    /// What is left to check is that the *live* value is plausible: a reading must
    /// not be zero, and two readings must not be identical after a spin.
    #[test]
    fn a_live_clock_reports_a_usable_value() {
        let c = StdClock::default();
        let a = c.now();
        let mut spins = 0u32;
        // Busy-wait rather than `sleep`: `sleep` would test the scheduler, and a
        // machine that preempts us mid-loop would make this flaky for the wrong
        // reason.
        while c.now().duration_since(a) < Duration::from_micros(200) && spins < 50_000_000 {
            spins = spins.wrapping_add(1);
            core::hint::black_box(spins);
        }
        let b = c.now();
        assert!(b > a, "a spin loop must advance the clock");
        let elapsed = b.duration_since(a);
        assert!(
            elapsed >= Duration::from_micros(200),
            "the loop asked for 200us and got {elapsed:?}"
        );
        // Nanoseconds, not milliseconds: 200µs is 200_000 ns, and if the
        // representation were milliseconds this would read as 0.
        assert!(
            elapsed.as_nanos() >= 200_000,
            "200us must not read as zero or as 200, got {elapsed:?}"
        );
    }

    /// Two clocks built with [`StdClock::since`] and the same origin agree, which
    /// is what makes a test able to compare two nodes' latencies at all.
    ///
    /// Two clocks with *independent* origins are **not** comparable, and that is
    /// documented behaviour rather than an accident: `StdClock::default` takes its
    /// origin when it is constructed, so an independently-constructed clock starts
    /// counting from its own moment and its readings have no defined relationship
    /// to another's. Preserving `std::time::Instant`'s property is deliberate —
    /// a core whose behaviour depended on two nodes' clocks agreeing would be a
    /// core that could not be reasoned about.
    #[test]
    fn a_shared_origin_makes_two_clocks_comparable() {
        let origin = StdInstant::now();
        let a = StdClock::since(origin);
        let b = StdClock::since(origin);
        let (ra, rb) = (a.now(), b.now());
        // Same epoch, so the difference is bounded by the work between the two
        // calls — not the ~584-year gap two independent origins would produce.
        assert!(
            rb.duration_since(ra) < Duration::from_secs(1),
            "a shared origin should keep two clocks close, got {:?}",
            rb.duration_since(ra)
        );
        // An independent origin is later than ours, so its readings start near
        // zero regardless of how much wall time has passed.
        let independent = StdClock::default();
        assert!(
            independent.origin() >= origin,
            "an independently-constructed clock takes a later origin"
        );
    }

    /// A clock's readings start an hour above the epoch, so a test can ask for a
    /// past instant at all.
    ///
    /// Without this, `Instant::saturating_sub` on a freshly-constructed clock
    /// clamps at zero and returns a *shorter* interval than asked for — silently,
    /// because `EPOCH` is a valid instant. Measured: a round-trip test asked for
    /// 20 ms and measured 8.35 ms, which is indistinguishable from a real loopback
    /// round trip.
    ///
    /// So the property is asserted on the clock, not left to whatever test happens
    /// to be the first to step backwards.
    #[test]
    fn a_clock_can_be_stepped_backwards_without_clamping() {
        let c = StdClock::default();
        let now = c.now();
        assert!(
            now.as_nanos() >= 3_600_000_000_000,
            "readings must start an hour above the epoch, got {} ns",
            now.as_nanos()
        );
        // The whole point: a test-sized step backwards is *exact*, not clamped.
        for ms in [1, 20, 30, 1_000, 60_000] {
            let earlier = now
                .ago_exact(Duration::from_millis(ms))
                .unwrap_or_else(|| panic!("{ms}ms backwards must be representable"));
            assert_eq!(
                now.duration_since(earlier),
                Duration::from_millis(ms),
                "{ms}ms must survive the step exactly"
            );
        }
        // And the clamp still exists for the case that genuinely has no past,
        // where a `None` is the honest answer.
        assert!(
            Instant::EPOCH.ago_exact(Duration::from_millis(1)).is_none(),
            "the epoch has no past, and must say so rather than clamp"
        );
    }

    /// The floor is an **offset**, not a shifted origin, so `origin()` still
    /// returns what the caller passed.
    ///
    /// The alternative — subtracting the floor from the `StdInstant` — is shorter to
    /// write and wrong twice over: [`StdInstant`] counts from *boot*, so a machine up
    /// for under an hour cannot be backed off by an hour and would panic on exactly
    /// the machines least likely to be running the suite; and `origin()` would stop
    /// being the caller's value, breaking the [`StdClock::since`] contract for no
    /// gain.
    #[test]
    fn the_origin_is_what_the_caller_passed() {
        let origin = StdInstant::now();
        assert_eq!(StdClock::since(origin).origin(), origin);
    }
}
