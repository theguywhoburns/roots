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

/// Which of Go's three link kinds a row is (`linkType`, `link.go:26-29`).
///
/// Go keeps all three in the one `_links` map (`link.go:54-57`), and so do we:
/// `addPeer` looks a row up by URI alone, so a listener's row can answer it just
/// as Go's does — which is why an inbound link is an [`Entry`], not a separate
/// table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// Statically configured: redial forever, backing off.
    Persistent,
    /// Multicast-discovered: one attempt, then forgotten.
    Ephemeral,
    /// The peer dialled us. Nobody redials it, and the row goes away with the
    /// link (Go's `defer delete(l._links, info)`, `link.go:567-571`).
    Incoming,
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
    /// home (`src/supervisor.rs`). Empty and unused on an [`LinkKind::Incoming`]
    /// row, which nobody ever redials.
    pub redial: SupervisedPeer,
    /// `?maxbackoff=` or Go's default (`1s << 12`).
    pub max_backoff: Duration,
    /// The link this row produced: node key *and* the identity of the socket
    /// that reaches it, while the node still holds that socket. The key alone
    /// cannot answer "is my link up" — the set keeps one slot per node key, so
    /// a peer that both dialled us and we dialled has two links and one slot,
    /// and only the id says which of the two a row is describing.
    pub live: Option<(roots::LinkId, [u8; 32])>,
    /// Last connection error, for `getPeers`/`getSelf` (Go's `link._err`).
    pub last_error: Option<String>,
    /// When `last_error` happened. `getPeers` reports the *age* of the error,
    /// not its time (Go's `time.Since(p.LastErrorTime)`, `getpeers.go:62`).
    pub err_at: Option<Instant>,
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
            err_at: None,
            dialing: None,
        });
        Ok(())
    }

    /// True when an inbound link may not claim this URI's row: somebody already
    /// holds a live connection there. Go checks the same thing before it stores
    /// the link and drops the newcomer silently — "If there's an existing link
    /// state for this link, get it. If this node is already connected to us,
    /// just drop the connection" (`link.go:529-541`).
    pub fn busy(&self, uri: &str) -> bool {
        self.find(uri, "").is_some_and(|at| {
            let e = &self.entries[at];
            e.live.is_some()
        })
    }

    /// Claim the row for a link a listener accepted (Go's inbound half of the
    /// listener goroutine).
    ///
    /// `uri` is built from the *accepted socket's* peer address, not from the
    /// listener's own, which is what makes it look like `tcp://192.0.2.7:51830`.
    /// Ask [`Links::busy`] first: a row that already has a link keeps it.
    pub fn accept(&mut self, uri: &str, conn: &AnyConn) {
        let live = (conn.id, conn.remote_key);
        if let Some(at) = self.find(uri, "") {
            let e = &mut self.entries[at];
            e.live = Some(live);
            e.last_error = None;
            e.err_at = None;
            return;
        }
        self.entries.push(Entry {
            uri: uri.to_string(),
            sintf: String::new(),
            kind: LinkKind::Incoming,
            redial: SupervisedPeer::new(uri.to_string()),
            max_backoff: backoff_cap(uri),
            live: Some(live),
            last_error: None,
            err_at: None,
            dialing: None,
        });
    }

    /// The id of the link this row currently holds, if any. Asked **before**
    /// [`Links::remove`], which forgets the row and with it the id.
    pub fn live_id(&self, uri: &str, sintf: &str) -> Option<roots::LinkId> {
        self.find(uri, sintf)
            .and_then(|at| self.entries[at].live)
            .map(|(id, _)| id)
    }

    /// Cancel the redial loop for a configured peer and forget the row.
    ///
    /// Go's `links.remove` does this *and* closes the live connection
    /// (`link.go:433-438`), so the row vanishes from `getPeers` together with the
    /// link. The caller closes the link, because only it holds the set; this
    /// returns the id that names it.
    ///
    /// Slice 5 deliberately kept the link open here, on the strength of the
    /// comment at `core/api.go:207-211` ("The peer is not disconnected
    /// immediately"). Reading Go rather than its comment showed the opposite
    /// (`link.go:438` is the `conn.Close()`), so the divergence is gone.
    pub fn remove(&mut self, uri: &str, sintf: &str) -> Result<(), LinkError> {
        let at = self.find(uri, sintf).ok_or(LinkError::NotConfigured)?;
        self.entries.remove(at);
        Ok(())
    }

    /// Start every dial that is due: not live, not already in flight, past its
    /// backoff. `SupervisedPeer::due`'s own live-URI gate is asked with an empty
    /// list because the entry carries that state here — the URI-list form is for
    /// a caller that tracks liveness somewhere other than the peer record.
    pub fn start_due(&mut self, now: Instant) {
        for at in 0..self.entries.len() {
            if self.entries[at].kind == LinkKind::Incoming
                || self.entries[at].live.is_some()
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
    pub fn mark_live(&mut self, token: u64, conn: &AnyConn) -> bool {
        let Some(e) = self.entry_mut(token) else {
            return false;
        };
        e.dialing = None;
        e.live = Some((conn.id, conn.remote_key));
        e.last_error = None;
        e.err_at = None;
        e.redial.record_success();
        true
    }

    /// Record a failed dial: back off, keep the error — and the moment it
    /// happened, because `getPeers` reports the error's *age* — and forget an
    /// ephemeral entry the way Go's goroutine exit deletes its map entry.
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
        e.err_at = Some(Instant::now());
        let cap = e.max_backoff;
        e.redial.record_failure(cap);
    }

    /// Reconcile against the links the set still holds. `serve` evicts a dead
    /// link silently, so this diff is how a vanished link becomes a redial again
    /// — and how a dead ephemeral or inbound link stops being remembered at all.
    ///
    /// Asked by [`roots::LinkId`], never by node key: the set keeps one slot per
    /// key, so a key still present does not mean *this* row's link still is.
    /// Reporting a dial as up because the same peer then dialled us is the bug
    /// this replaces.
    pub fn note_liveness(&mut self, links: &LinkSet) {
        let mut drop: Vec<usize> = Vec::new();
        for at in 0..self.entries.len() {
            let e = &mut self.entries[at];
            let Some((id, _)) = e.live else { continue };
            if links.stats(id).is_some() {
                continue;
            }
            e.live = None;
            let cap = e.max_backoff;
            e.redial.record_failure(cap);
            if e.kind != LinkKind::Persistent {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> (Links, mpsc::UnboundedReceiver<LinkEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        (Links::new(Client::new(key), tx), rx)
    }

    /// One real, handshaked link — both test links share a peer key, which is
    /// the case that matters. A [`roots::LinkId`] cannot be minted by hand, and
    /// that is the whole point of it, so a test that needs one makes a
    /// connection.
    async fn live_link() -> AnyConn {
        use roots::link::{accept, dial, listen};
        let ours = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let theirs = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let opts = roots::LinkOptions::default();
        let listener = listen("tcp://127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_opts = opts.clone();
        let server = tokio::spawn(async move {
            let conn = accept(&listener, &theirs, &server_opts).await.unwrap();
            drop(conn);
        });
        let conn = dial(&format!("tcp://{addr}"), &ours, &opts).await.unwrap();
        let _ = server.await;
        AnyConn::new(conn)
    }

    #[tokio::test]
    async fn an_inbound_link_gets_a_row_of_its_own() {
        // Go's `_links` map holds inbound rows beside configured ones, keyed by
        // a URI built from the accepted socket's peer address (`link.go:514-524`),
        // and `links.add` looks that map up by URI alone — so a peer that dialled
        // us is listed, and dialling it back says "already configured".
        let (mut m, _rx) = manager();
        let conn = live_link().await;
        let (key, id) = (conn.remote_key, conn.id);
        m.accept("tcp://127.0.0.1:51830", &conn);
        assert_eq!(m.len(), 1, "an accepted link is a row");
        assert_eq!(m.entries[0].kind, LinkKind::Incoming);
        assert_eq!(m.entries[0].live, Some((id, key)));
        assert!(
            m.busy("tcp://127.0.0.1:51830"),
            "the row holds a live link, so a second connection to that address is dropped"
        );
        assert!(
            !m.busy("tcp://127.0.0.1:51831"),
            "a different peer address is a different row"
        );
        assert_eq!(
            m.add("tcp://127.0.0.1:51830", "", LinkKind::Persistent),
            Err(LinkError::AlreadyConfigured),
            "Go's dedup key does not care which way the link came up"
        );
    }

    #[tokio::test]
    async fn a_dead_inbound_row_disappears_and_a_dead_dial_row_stays() {
        // Go's inbound handler ends with `defer delete(l._links, info)`
        // (`link.go:567-571`), so an accepted link leaves `getPeers` when it
        // dies; a configured row stays behind and reports `up: false` plus its
        // last error until the operator removes it.
        let (mut m, _rx) = manager();
        let conn = live_link().await;
        let (id, key) = (conn.id, conn.remote_key);
        m.accept("tcp://127.0.0.1:51830", &conn);
        m.add("tcp://127.0.0.1:9001", "", LinkKind::Persistent)
            .unwrap();
        m.entries[1].live = Some((id, key));
        let mut links = LinkSet::single(conn);
        m.note_liveness(&links);
        assert_eq!(m.len(), 2, "both rows hold the link, so both stay");
        drop(links.remove(id));
        m.note_liveness(&links);
        assert_eq!(m.len(), 1, "the inbound row is deleted with its link");
        assert_eq!(m.entries[0].uri, "tcp://127.0.0.1:9001");
        assert_eq!(
            m.entries[0].live, None,
            "the dial row stays, reported down, and is due to redial"
        );
    }

    #[tokio::test]
    async fn liveness_is_asked_of_the_link_a_row_holds() {
        // The set holds one entry per **link**, so a row must be asked about the
        // connection it holds and not about the node. Asking per node key would
        // report a dead row as up because the peer has some other connection.
        let (mut m, _rx) = manager();
        let held = live_link().await;
        let lost = live_link().await;
        assert_eq!(
            held.remote_key, lost.remote_key,
            "two links to the same peer is the case under test"
        );
        m.add("tcp://127.0.0.1:9001", "", LinkKind::Persistent)
            .unwrap();
        m.entries[0].live = Some((lost.id, held.remote_key));
        // Both links are in the set now, which is what ironwood does
        // (`peers map[publicKey]map[*peer]struct{}`, `peers.go:32`).
        let mut links = LinkSet::single(held);
        let lost_id = lost.id;
        links.add(lost);
        m.note_liveness(&links);
        assert!(
            m.entries[0].live.is_some(),
            "the row's own link is up, so the row is up"
        );
        // Drop that link and the row must notice, even though the peer still has
        // the other one in the set.
        assert_eq!(links.ids().len(), 2, "two links to one node, both live");
        let _ = links.remove(lost_id);
        m.note_liveness(&links);
        assert_eq!(
            m.entries[0].live, None,
            "its own link is gone, so the row is down even though the peer has another"
        );
        assert_eq!(m.len(), 1, "and a persistent row is not forgotten");
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
        assert!(
            m.entries[0].err_at.is_some(),
            "`getPeers` prints how long ago the error was, so the moment is kept"
        );
        assert_eq!(m.entries[0].sintf, "");
        assert_eq!(m.entries[0].live, None, "reported down");
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
        let conn = live_link().await;
        assert!(
            !m.mark_live(token, &conn),
            "the peer was removed mid-dial, so the caller must drop the link"
        );
    }
}
