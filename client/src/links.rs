//! The link manager: Go's `links.add` bookkeeping
//! (`reference/yggdrasil-go/src/core/link.go:160-330`). One entry per
//! `(link_id, sintf)` — duplicate URIs kick the existing entry instead of
//! stacking — plus the per-URI redial clock and the last connection error,
//! which is what Go's `getPeers`/`getSelf` report for a peer.
//!
//! Dials are the only node work that runs off the node task: connecting and the
//! `meta` handshake touch no router state, so spawning an attempt costs the
//! single-task invariant nothing. A task reports back over [`LinkEvent`] and the
//! node task stays the only place a `Router` is touched.

use std::fmt;
use std::time::{Duration, Instant};

use roots::link::parse_link_uri;
use roots::{AnyConn, Client, Error, LinkSet, SupervisedPeer, backoff_cap};
use tokio::sync::mpsc;

/// Go's `linkInfo.uri`, which comes from `urlForLinkInfo` (`link.go:766-769`):
/// the peering URI with its query blanked, so `tls://h:p?password=x` and
/// `tls://h:p?key=ab..` name the same link. Go keeps a URL fragment because
/// `url.URL.String()` does; peering URIs never carry one, so splitting on `?` is
/// the whole difference.
pub fn link_id(uri: &str) -> String {
    match uri.split_once('?') {
        Some((head, _)) => head.to_string(),
        None => uri.to_string(),
    }
}

/// The dedup key: URI-minus-query plus the source interface it was dialled from
/// (`linkInfo`, `link.go:54-57`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Info {
    pub link_id: String,
    pub sintf: String,
}

impl Info {
    pub fn new(uri: &str, sintf: &str) -> Self {
        Self {
            link_id: link_id(uri),
            sintf: sintf.to_string(),
        }
    }
}

/// Whether a dialled link outlives its failures (`linkType`, `link.go:26-29`).
/// Go's third kind, `linkTypeIncoming`, never enters the map at all: an accepted
/// link belongs to its listener, not to a configured peer. So inbound links
/// arrive at the node as `Cmd::Accept` with no entry behind them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// Statically configured: redial forever, backing off.
    Persistent,
    /// Multicast-discovered: one attempt, then forgotten.
    Ephemeral,
}

/// Why `add`/`remove` refused. The first two strings are Go's verbatim
/// (`link.go:148-152`), because the admin socket echoes them to `yggdrasilctl`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    AlreadyConfigured,
    NotConfigured,
    /// Our URI parser said no (unknown scheme, bad `?maxbackoff=`, oversize
    /// password …). The message is ours: Go raises a per-option error while it
    /// parses, and the admin slice is where those strings get pinned.
    InvalidUri(String),
}

impl LinkError {
    pub fn message(&self) -> String {
        match self {
            LinkError::AlreadyConfigured => "peer is already configured".into(),
            LinkError::NotConfigured => "peer is not configured".into(),
            LinkError::InvalidUri(m) => m.clone(),
        }
    }
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for LinkError {}

/// What a dial task brings back. Package-private on purpose: it is the node's
/// own plumbing, not something a caller sends.
#[derive(Debug)]
pub(crate) enum LinkEvent {
    Dialed {
        token: u64,
        uri: String,
        outcome: Result<AnyConn, Error>,
    },
}

/// One configured peer.
#[derive(Debug)]
pub struct Entry {
    pub uri: String,
    pub sintf: String,
    pub kind: LinkKind,
    /// Redial policy data — the library's, so the backoff arithmetic has one
    /// home (`src/supervisor.rs`).
    pub redial: SupervisedPeer,
    /// `?maxbackoff=` or Go's default (`1s << 12`).
    pub max_backoff: Duration,
    /// Node key of the link this URI produced, while the node still holds it.
    pub live: Option<[u8; 32]>,
    /// Last connection error, for `getPeers`/`getSelf` (Go's `link._err`).
    pub last_error: Option<String>,
    /// Token of the in-flight dial, if any. A result whose token matches no
    /// entry is stale — the peer was removed while we were dialling.
    dialing: Option<u64>,
}

/// The configured-peer list plus the dial tasks it owns. Entries stay in
/// configuration order, which is the order Go's admin socket walks them.
pub struct Links {
    client: Client,
    events: mpsc::UnboundedSender<LinkEvent>,
    entries: Vec<Entry>,
    next_token: u64,
}

impl Links {
    pub(crate) fn new(client: Client, events: mpsc::UnboundedSender<LinkEvent>) -> Self {
        Self {
            client,
            events,
            entries: Vec::new(),
            next_token: 0,
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn find(&self, uri: &str, sintf: &str) -> Option<usize> {
        let want = Info::new(uri, sintf);
        self.entries
            .iter()
            .position(|e| Info::new(&e.uri, &e.sintf) == want)
    }

    /// Go `links.add`: validate the URI, then look for an existing entry — and
    /// if there is one, kick it and report `AlreadyConfigured` instead of
    /// dialling twice (`link.go:236-245`).
    ///
    /// Our kick is `next_retry = now`. Go interrupts a backoff sleep on a `kick`
    /// channel; waking the next tick reaches the same outcome with one less
    /// channel per entry, at the cost of up to one tick of latency.
    pub fn add(&mut self, uri: &str, sintf: &str, kind: LinkKind) -> Result<(), LinkError> {
        parse_link_uri(uri).map_err(|e| LinkError::InvalidUri(e.to_string()))?;
        if let Some(at) = self.find(uri, sintf) {
            self.entries[at].redial.next_retry = Instant::now();
            return Err(LinkError::AlreadyConfigured);
        }
        self.entries.push(Entry {
            uri: uri.to_string(),
            sintf: sintf.to_string(),
            kind,
            redial: SupervisedPeer::new(uri.to_string()),
            max_backoff: backoff_cap(uri),
            live: None,
            last_error: None,
            dialing: None,
        });
        Ok(())
    }

    /// Go `links.remove`: cancel the redial loop. The live link is left alone —
    /// Go's `RemovePeer` says so out loud ("The peer is not disconnected
    /// immediately", `core/api.go:207-211`) and `getPeers` keeps listing it until
    /// it dies on its own.
    pub fn remove(&mut self, uri: &str, sintf: &str) -> Result<(), LinkError> {
        let at = self.find(uri, sintf).ok_or(LinkError::NotConfigured)?;
        self.entries.remove(at);
        Ok(())
    }

    /// Start every dial that is due: not live, not already in flight, past its
    /// backoff. `SupervisedPeer::due`'s own live-URI gate is asked with an empty
    /// list because the entry carries that state here — the URI-list form is what
    /// `examples/admin.rs`, which has no per-entry liveness, needs.
    pub fn start_due(&mut self, now: Instant) {
        for at in 0..self.entries.len() {
            if self.entries[at].live.is_some()
                || self.entries[at].dialing.is_some()
                || !self.entries[at].redial.due(now, &[])
            {
                continue;
            }
            let token = self.next_token;
            self.next_token += 1;
            self.entries[at].dialing = Some(token);
            let client = Client {
                key: self.client.key.clone(),
                opts: self.client.opts.clone(),
            };
            let events = self.events.clone();
            let uri = self.entries[at].uri.clone();
            tokio::spawn(async move {
                let outcome = client.connect_any(&uri).await;
                let _ = events.send(LinkEvent::Dialed {
                    token,
                    uri,
                    outcome,
                });
            });
        }
    }

    /// Record that a dial produced a live link. Returns false when the entry is
    /// gone, in which case the caller must drop the connection — which is what
    /// Go does when a peering has already come up on that entry
    /// (`link.go:366-373`).
    pub fn mark_live(&mut self, token: u64, peer: [u8; 32]) -> bool {
        let Some(e) = self.entry_mut(token) else {
            return false;
        };
        e.dialing = None;
        e.live = Some(peer);
        e.last_error = None;
        e.redial.record_success();
        true
    }

    /// Record a failed dial: back off, keep the error for the report, and forget
    /// an ephemeral entry the way Go's goroutine exit deletes its map entry.
    pub fn mark_failed(&mut self, token: u64, err: &str) {
        let Some(at) = self.entries.iter().position(|e| e.dialing == Some(token)) else {
            return;
        };
        if self.entries[at].kind == LinkKind::Ephemeral {
            self.entries.remove(at);
            return;
        }
        let e = &mut self.entries[at];
        e.dialing = None;
        e.live = None;
        e.last_error = Some(err.to_string());
        let cap = e.max_backoff;
        e.redial.record_failure(cap);
    }

    /// Reconcile against the links the set still holds. `serve` evicts a dead
    /// link silently, so this diff is how a vanished link becomes a redial again
    /// — and how a dead ephemeral link stops being remembered at all.
    pub fn note_liveness(&mut self, links: &LinkSet) {
        let held = links.peers();
        let mut drop: Vec<usize> = Vec::new();
        for at in 0..self.entries.len() {
            let e = &mut self.entries[at];
            let Some(key) = e.live else { continue };
            if held.contains(&key) {
                continue;
            }
            e.live = None;
            let cap = e.max_backoff;
            e.redial.record_failure(cap);
            if e.kind == LinkKind::Ephemeral {
                drop.push(at);
            }
        }
        for at in drop.into_iter().rev() {
            self.entries.remove(at);
        }
    }

    fn entry_mut(&mut self, token: u64) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.dialing == Some(token))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// One row per configured peer — `uri`, `sintf`, up-or-down, last error —
    /// which is what Go's `getPeers` puts in `peers[]` and `getSelf` in `lists`.
    pub fn report(&self) -> Vec<(String, String, bool, Option<String>)> {
        self.entries
            .iter()
            .map(|e| {
                (
                    e.uri.clone(),
                    e.sintf.clone(),
                    e.live.is_some(),
                    e.last_error.clone(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> (Links, mpsc::UnboundedReceiver<LinkEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        (Links::new(Client::new(key), tx), rx)
    }

    #[test]
    fn link_id_strips_query() {
        assert_eq!(link_id("tls://h:p?password=x&a=b"), "tls://h:p");
        assert_eq!(link_id("tcp://127.0.0.1:1234"), "tcp://127.0.0.1:1234");
        assert_eq!(
            Info::new("tls://h:p?key=aa", "eth0"),
            Info::new("tls://h:p?key=bb", "eth0")
        );
        assert_ne!(
            Info::new("tls://h:p", "eth0"),
            Info::new("tls://h:p", "eth1"),
            "one URI on two interfaces is two links: `sintf` is the other half of the key"
        );
    }

    #[test]
    fn duplicate_dial_is_already_configured_and_kicked() {
        let (mut m, _rx) = manager();
        m.add("tcp://127.0.0.1:9001?password=x", "", LinkKind::Persistent)
            .expect("first add configures");
        // Push the retry out, then add the same link with different options.
        m.entries[0].redial.next_retry = Instant::now() + Duration::from_secs(600);
        assert!(
            !m.entries[0].redial.due(Instant::now(), &[]),
            "backing off before the kick"
        );
        assert_eq!(
            m.add("tcp://127.0.0.1:9001?password=y", "", LinkKind::Persistent),
            Err(LinkError::AlreadyConfigured)
        );
        assert_eq!(m.len(), 1, "a duplicate never stacks");
        assert!(
            m.entries[0].redial.due(Instant::now(), &[]),
            "the duplicate kicked the backoff, as Go's state.kick does"
        );
    }

    #[test]
    fn remove_matches_the_dedup_key_and_cancels_redial() {
        let (mut m, _rx) = manager();
        m.add("tcp://127.0.0.1:9001", "", LinkKind::Persistent)
            .unwrap();
        assert_eq!(
            m.remove("tcp://127.0.0.1:9001?password=x", ""),
            Ok(()),
            "removed by link_id, not by the exact URI that was added"
        );
        assert_eq!(
            m.remove("tcp://127.0.0.1:9001", ""),
            Err(LinkError::NotConfigured)
        );
        assert!(m.is_empty());
    }

    #[test]
    fn bad_uri_is_refused_before_it_is_stored() {
        let (mut m, _rx) = manager();
        assert!(matches!(
            m.add("carrier://h:p", "", LinkKind::Persistent),
            Err(LinkError::InvalidUri(_))
        ));
        assert!(m.is_empty());
    }

    #[tokio::test]
    async fn failed_dial_backs_off_and_reports() {
        // Nothing listens on 9001, so the spawned attempt comes back with a
        // connection error: the entry must survive (it is persistent), stop being
        // in flight, and be scheduled later.
        let (mut m, mut rx) = manager();
        m.add(
            "tcp://127.0.0.1:9001?maxbackoff=5s",
            "",
            LinkKind::Persistent,
        )
        .unwrap();
        m.start_due(Instant::now());
        let LinkEvent::Dialed { token, outcome, .. } = rx.recv().await.expect("event");
        assert!(outcome.is_err(), "loopback connect to a closed port fails");
        m.mark_failed(token, "connection refused");
        assert!(!m.entries[0].redial.due(Instant::now(), &[]), "backing off");
        assert_eq!(
            m.entries[0].last_error.as_deref(),
            Some("connection refused")
        );
        assert_eq!(m.report()[0].1, "");
        assert!(!m.report()[0].2, "reported down");
        assert_eq!(
            m.entries[0].dialing, None,
            "the attempt is over, so the next one is gated only by the backoff"
        );
    }

    #[tokio::test]
    async fn ephemeral_failure_is_forgotten() {
        let (mut m, mut rx) = manager();
        m.add("tcp://127.0.0.1:9001", "", LinkKind::Ephemeral)
            .unwrap();
        m.start_due(Instant::now());
        let LinkEvent::Dialed { token, .. } = rx.recv().await.expect("event");
        m.mark_failed(token, "no route");
        assert!(
            m.is_empty(),
            "Go's ephemeral link goroutine exits and deletes its map entry"
        );
    }

    #[tokio::test]
    async fn stale_dial_result_finds_no_entry() {
        let (mut m, mut rx) = manager();
        m.add("tcp://127.0.0.1:9001", "", LinkKind::Persistent)
            .unwrap();
        m.start_due(Instant::now());
        let LinkEvent::Dialed { token, .. } = rx.recv().await.expect("event");
        m.remove("tcp://127.0.0.1:9001", "").unwrap();
        assert!(
            !m.mark_live(token, [7; 32]),
            "the peer was removed mid-dial, so the caller must drop the link"
        );
    }
}
