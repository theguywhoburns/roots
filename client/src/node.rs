//! The node: one task that owns the `Router`, the `LinkSet` and the mailbox
//! every other task talks to.
//!
//! This is Go's actor shape (`Core` and its `links` actor,
//! `reference/yggdrasil-go/src/core/link.go`) collapsed into a single task, and
//! the reason the library needs no lock: only `run` touches router state, so
//! listeners, redial tasks and (from Slice 7) the admin socket all hand work
//! over as [`Cmd`]s instead of reaching in. It replaces the old one-link-per-task
//! `run_peer`, which duplicated the redial policy that `Links` now owns.

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use roots::{AnyConn, Client, LinkSet, Router};
use tokio::sync::{mpsc, oneshot};

use crate::links::{LinkError, LinkEvent, LinkKind, Links, link_id};

/// How long a serve slice runs before the mailbox is drained again. Go's actor
/// has the same property — a message waits while the handler runs — and 50 ms
/// keeps a `yggdrasilctl` round trip imperceptible while leaving a slice long
/// enough for a peer's keepalive to land.
pub const DEFAULT_TICK: Duration = Duration::from_millis(50);

/// One configured peer, joined with the link it produced. This is Go's
/// `PeerInfo` (`core/api.go:22-40`) minus the fields the router cannot name
/// yet: rates.
#[derive(Debug)]
pub struct PeerRow {
    pub uri: String,
    pub sintf: String,
    /// Node key of the live link, if this entry has one.
    pub key: Option<[u8; 32]>,
    pub up: bool,
    pub inbound: bool,
    pub port: u64,
    pub priority: u8,
    /// Go's `_getCost` (`ironwood/network/router.go:221-228`): the lag estimate
    /// in whole milliseconds, floored at 1 because the routing maths divides by
    /// it. Go's `latency` is a separate number — the raw last SigReq round trip,
    /// which the library does not keep — so it stays Slice 8's.
    pub cost: u64,
    pub up_for: Duration,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_error: Option<String>,
}

/// Everything the admin socket may ask the node about, gathered by the node
/// task itself. A snapshot rather than a per-command query because the asking
/// is the expensive part: it has to wait for the tick.
#[derive(Debug)]
pub struct Snapshot {
    pub key: [u8; 32],
    /// Go's `routing_entries`: the size of the tree's node table
    /// (`ironwood/network/debug.go:64`).
    pub routing_entries: usize,
    pub tree: Vec<([u8; 32], [u8; 32], u64)>,
    pub paths: Vec<([u8; 32], Vec<u64>, u64)>,
    pub sessions: Vec<[u8; 32]>,
    pub peers: Vec<PeerRow>,
}

/// One request to the node. Every way in to a running node is a variant of this.
#[derive(Debug)]
pub enum Cmd {
    /// Configure a peer and start dialling it. `persistent` is Go's
    /// `linkTypePersistent` (static config, redials forever) versus
    /// `linkTypeEphemeral` (multicast-discovered: one attempt, then forgotten).
    ///
    /// `respond` is how the admin socket learns that the URI was refused —
    /// Go's `addPeer` answers `peer is already configured`, and a peer list
    /// built from a config file has nobody to tell.
    Dial {
        uri: String,
        sintf: String,
        persistent: bool,
        respond: Option<oneshot::Sender<Result<(), LinkError>>>,
    },
    /// Stop redialling a configured peer. The live link is left alone, exactly
    /// as in Go (`core/api.go:207-211`).
    Drop {
        uri: String,
        sintf: String,
        respond: Option<oneshot::Sender<Result<(), LinkError>>>,
    },
    /// A listener finished handshaking an inbound link. No entry behind it:
    /// inbound links belong to their listener, not to the peer list.
    Accept { conn: AnyConn },
    /// Queue a session payload for `dest`. (Slice 12 adds the IPv6-keyed
    /// resolve-and-hold form that a TUN needs; this is the one an app that
    /// already knows a node key wants.)
    Send { dest: [u8; 32], bytes: Vec<u8> },
    /// Answer with the node's whole readable state, then carry on.
    Report { respond: oneshot::Sender<Snapshot> },
    /// Leave the loop after the current slice.
    Quit,
}

/// A running node. Build one with [`Node::new`], hand the sender to whatever
/// produces work, then `run` it — in the task that owns it, which is the only
/// task that ever touches its router.
pub struct Node {
    router: Router,
    links: LinkSet,
    peers: Links,
    rx: mpsc::UnboundedReceiver<Cmd>,
    tx: mpsc::UnboundedSender<Cmd>,
    events: mpsc::UnboundedReceiver<LinkEvent>,
    outbox: Vec<([u8; 32], Vec<u8>)>,
    tick: Duration,
    quit: bool,
}

impl Node {
    pub fn new(key: SigningKey) -> (Self, mpsc::UnboundedSender<Cmd>) {
        Self::with_tick(key, DEFAULT_TICK)
    }

    pub fn with_tick(key: SigningKey, tick: Duration) -> (Self, mpsc::UnboundedSender<Cmd>) {
        Self::from_client(Client::new(key), tick)
    }

    /// The constructor a config-driven node uses: the `Client` carries the link
    /// options (password, allowlist) the dials and handshakes are made with, so
    /// a caller that built them must not have them reset to the defaults.
    pub fn from_client(client: Client, tick: Duration) -> (Self, mpsc::UnboundedSender<Cmd>) {
        let router = Router::new(client.key.clone());
        let (tx, rx) = mpsc::unbounded_channel();
        let (etx, events) = mpsc::unbounded_channel();
        let node = Self {
            router,
            links: LinkSet::default(),
            peers: Links::new(client, etx),
            rx,
            tx,
            events,
            outbox: Vec::new(),
            tick,
            quit: false,
        };
        let sender = node.tx.clone();
        (node, sender)
    }

    pub fn sender(&self) -> mpsc::UnboundedSender<Cmd> {
        self.tx.clone()
    }

    /// The configured-peer bookkeeping, for a caller that has the node itself:
    /// a running node must be asked over [`Cmd::Report`] instead, because
    /// `run` holds the borrow.
    pub fn peers(&self) -> &Links {
        &self.peers
    }

    /// Read the router and the link set from inside the node task, which is the
    /// only place either may be read while the node runs.
    fn snapshot(&self) -> Snapshot {
        let known: Vec<([u8; 32], u64, u8, u128)> = self
            .router
            .link_peers()
            .into_iter()
            .map(|(key, port, priority, _, lag_ms)| (key, port, priority, lag_ms))
            .collect();
        let peers = self
            .peers
            .entries()
            .iter()
            .map(|e| {
                let stats = e.live.as_ref().and_then(|k| self.links.stats(k));
                let known = e
                    .live
                    .as_ref()
                    .and_then(|k| known.iter().find(|(key, ..)| key == k));
                let (port, priority, cost) = known
                    // `LinkSet::stats` and `tree.peers` are both keyed by node
                    // key, so a link the router has not adopted yet has no port,
                    // no priority and no cost to report — Go's `conns[conn]`
                    // lookup misses the same way (`core/api.go:96-103`).
                    .map(|(_, port, priority, lag)| (*port, *priority, (*lag).max(1) as u64))
                    .unwrap_or((0, 0, 0));
                PeerRow {
                    // Go reports the *link* URI, not the operator's: `PeerInfo.URI
                    // = info.uri` (`core/api.go:83`) and that map key went through
                    // `urlForLinkInfo` (`link.go:766-769`), which blanks the query.
                    // So `?password=` is never echoed back over the admin socket —
                    // which matters, because it is a secret.
                    uri: link_id(&e.uri),
                    sintf: e.sintf.clone(),
                    key: e.live,
                    up: stats.is_some(),
                    inbound: stats.as_ref().is_some_and(|s| s.inbound),
                    port,
                    priority,
                    cost,
                    up_for: stats.as_ref().map(|s| s.up).unwrap_or_default(),
                    rx_bytes: stats.as_ref().map(|s| s.rx_bytes).unwrap_or(0),
                    tx_bytes: stats.as_ref().map(|s| s.tx_bytes).unwrap_or(0),
                    last_error: e.last_error.clone(),
                }
            })
            .collect();
        Snapshot {
            key: self.router.pubkey(),
            routing_entries: self.router.known_nodes(),
            tree: self.router.tree_entries(),
            paths: self.router.get_paths(),
            sessions: self.router.get_sessions(),
            peers,
        }
    }

    /// The one loop: drain commands, drain dial results, reconcile liveness,
    /// start due dials, serve one slice. A command waits at most `tick`.
    pub async fn run(&mut self) -> Result<(), roots::Error> {
        while !self.quit {
            while let Ok(cmd) = self.rx.try_recv() {
                self.on_cmd(cmd).await;
            }
            while let Ok(ev) = self.events.try_recv() {
                self.on_dial(ev).await;
            }
            self.peers.note_liveness(&self.links);
            self.peers.start_due(Instant::now());
            // A dead link is not a dead node: we keep serving whoever is left.
            // `is_link` is the whole fatality gate (`router::fatal_link_error`).
            if let Err(e) = self
                .router
                .serve(&mut self.links, Some(self.tick), &mut self.outbox)
                .await
                && !e.is_link()
            {
                return Err(e);
            }
        }
        Ok(())
    }

    async fn on_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Dial {
                uri,
                sintf,
                persistent,
                respond,
            } => {
                let kind = if persistent {
                    LinkKind::Persistent
                } else {
                    LinkKind::Ephemeral
                };
                let outcome = self.peers.add(&uri, &sintf, kind);
                match (respond, &outcome) {
                    // The admin socket answers `peer is already configured`; a
                    // config file's peer list has no listener, so stderr is all
                    // the operator gets. Go logs the duplicate too
                    // (`link.go:242`, whose caller is `Core.AddPeer`).
                    (Some(respond), _) => {
                        let _ = respond.send(outcome);
                    }
                    (None, Err(e)) if *e != LinkError::AlreadyConfigured => {
                        eprintln!("peer {uri}: {e}");
                    }
                    (None, _) => {}
                }
            }
            Cmd::Drop {
                uri,
                sintf,
                respond,
            } => {
                let outcome = self.peers.remove(&uri, &sintf);
                match (respond, &outcome) {
                    (Some(respond), _) => {
                        let _ = respond.send(outcome);
                    }
                    (None, Err(e)) => eprintln!("peer {uri}: {e}"),
                    (None, Ok(())) => {}
                }
            }
            Cmd::Accept { mut conn } => {
                let peer = conn.remote_key;
                if let Err(e) = self.router.register(&mut conn, peer).await {
                    eprintln!("inbound link dropped: {e}");
                    return;
                }
                self.links.add(conn);
            }
            Cmd::Report { respond } => {
                let _ = respond.send(self.snapshot());
            }
            Cmd::Send { dest, bytes } => self.outbox.push((dest, bytes)),
            Cmd::Quit => self.quit = true,
        }
    }

    async fn on_dial(&mut self, ev: LinkEvent) {
        let LinkEvent::Dialed {
            token,
            uri,
            outcome,
        } = ev;
        let mut conn = match outcome {
            Err(e) => {
                // Go logs the same line at debug level and lets the backoff
                // decide when to try again (`link.go:390-397`).
                eprintln!("dial {uri}: {e}");
                self.peers.mark_failed(token, &e.to_string());
                return;
            }
            Ok(conn) => conn,
        };
        let peer = conn.remote_key;
        if let Err(e) = self.router.register(&mut conn, peer).await {
            eprintln!("dial {uri}: {e}");
            self.peers.mark_failed(token, &e.to_string());
            return;
        }
        if self.peers.mark_live(token, peer) {
            self.links.add(conn);
        }
        // Otherwise the peer was dropped while we were dialling, and dropping the
        // connection here is Go's "if a peering has come up in this time, abort
        // this one" (`link.go:366-373`).
    }
}
