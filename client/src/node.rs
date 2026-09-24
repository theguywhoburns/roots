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
use tokio::sync::mpsc;

use crate::links::{LinkError, LinkEvent, LinkKind, Links};

/// How long a serve slice runs before the mailbox is drained again. Go's actor
/// has the same property — a message waits while the handler runs — and 50 ms
/// keeps a `yggdrasilctl` round trip imperceptible while leaving a slice long
/// enough for a peer's keepalive to land.
pub const DEFAULT_TICK: Duration = Duration::from_millis(50);

/// One request to the node. Every way in to a running node is a variant of this.
#[derive(Debug)]
pub enum Cmd {
    /// Configure a peer and start dialling it. `persistent` is Go's
    /// `linkTypePersistent` (static config, redials forever) versus
    /// `linkTypeEphemeral` (multicast-discovered: one attempt, then forgotten).
    Dial {
        uri: String,
        sintf: String,
        persistent: bool,
    },
    /// Stop redialling a configured peer. The live link is left alone, exactly
    /// as in Go (`core/api.go:207-211`).
    Drop { uri: String, sintf: String },
    /// A listener finished handshaking an inbound link. No entry behind it:
    /// inbound links belong to their listener, not to the peer list.
    Accept { conn: AnyConn },
    /// Queue a session payload for `dest`. (Slice 12 adds the IPv6-keyed
    /// resolve-and-hold form that a TUN needs; this is the one an app that
    /// already knows a node key wants.)
    Send { dest: [u8; 32], bytes: Vec<u8> },
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
        let client = Client::new(key);
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

    /// The configured-peer bookkeeping, for a caller that wants to report it
    /// (the admin socket's `getPeers`, from Slice 7).
    pub fn peers(&self) -> &Links {
        &self.peers
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
            } => {
                let kind = if persistent {
                    LinkKind::Persistent
                } else {
                    LinkKind::Ephemeral
                };
                if let Err(e) = self.peers.add(&uri, &sintf, kind)
                    && e != LinkError::AlreadyConfigured
                {
                    eprintln!("peer {uri}: {e}");
                }
            }
            Cmd::Drop { uri, sintf } => {
                if let Err(e) = self.peers.remove(&uri, &sintf) {
                    eprintln!("peer {uri}: {e}");
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
