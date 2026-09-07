//! Persistent peer supervision: Go-style per-URI redial with backoff.
//!
//! Extracted from `examples/admin.rs` (`PeerCfg`) and the dead
//! `Client::drive` in `src/lib.rs`: one entry per configured URI, failures
//! counted, next retry gated by `backoff_delay(failures, cap)` where `cap`
//! comes from `?maxbackoff=` or `DEFAULT_MAX_BACKOFF`. Removal forgets the
//! entry (drops immediately); the driver loop redials the rest.

use std::time::{Duration, Instant};

/// One configured peer: redial state for a single URI.
#[derive(Debug, Clone)]
pub struct SupervisedPeer {
    /// Peer URI as configured (all schemes).
    pub uri: String,
    /// Consecutive failures (saturates at 32).
    pub failures: u32,
    /// When the next dial attempt is due.
    pub next_retry: Instant,
}

impl SupervisedPeer {
    pub fn new(uri: String) -> Self {
        Self {
            uri,
            failures: 0,
            next_retry: Instant::now(),
        }
    }

    /// Record a successful dial: reset backoff.
    pub fn record_success(&mut self) {
        self.failures = 0;
        self.next_retry = Instant::now();
    }

    /// Record a failed dial: bump failures and push `next_retry` out by
    /// `backoff_delay`, capped per URI (`?maxbackoff=`) or the default.
    pub fn record_failure(&mut self, cap: Duration) {
        self.failures = self.failures.saturating_add(1).min(32);
        self.next_retry = Instant::now() + crate::link::backoff_delay(self.failures, cap);
    }

    /// True when a dial attempt is due and no live link owns this URI.
    pub fn due(&self, now: Instant, live_uris: &[String]) -> bool {
        now >= self.next_retry && !live_uris.contains(&self.uri)
    }
}

/// Backoff cap for one URI: `?maxbackoff=` else the Go default.
pub fn backoff_cap(uri: &str) -> Duration {
    crate::link::parse_link_uri(uri)
        .ok()
        .and_then(|(_, p)| p.max_backoff)
        .unwrap_or(crate::link::DEFAULT_MAX_BACKOFF)
}

/// Indices due for (re)dial, in configuration order.
pub fn due_indices(
    configured: &[SupervisedPeer],
    now: Instant,
    live_uris: &[String],
) -> Vec<usize> {
    configured
        .iter()
        .enumerate()
        .filter(|(_, c)| c.due(now, live_uris))
        .map(|(i, _)| i)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_resets_backoff() {
        let mut p = SupervisedPeer::new("tcp://h:1".to_string());
        p.record_failure(Duration::from_secs(60));
        assert_eq!(p.failures, 1);
        p.record_success();
        assert_eq!(p.failures, 0);
    }

    #[test]
    fn due_gates_on_live_and_time() {
        let mut p = SupervisedPeer::new("tcp://h:1".to_string());
        assert!(p.due(Instant::now(), &[]));
        assert!(!p.due(Instant::now(), &["tcp://h:1".to_string()]));
        p.record_failure(Duration::from_secs(3600));
        assert!(!p.due(Instant::now(), &[]));
    }

    #[test]
    fn backoff_cap_defaults_and_parses() {
        assert_eq!(backoff_cap("tcp://h:1"), crate::link::DEFAULT_MAX_BACKOFF);
        assert_eq!(
            backoff_cap("tcp://h:1?maxbackoff=30s"),
            Duration::from_secs(30)
        );
    }
}
