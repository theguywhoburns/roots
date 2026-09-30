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

/// One row of Go's `_links` map, joined with what the router and the socket
/// say about it — Go's `PeerInfo` (`core/api.go:22-40`), which `GetPeers`
/// builds the same way: iterate the link table, then look the connection up in
/// the router's own peer list by identity.
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
    /// it.
    pub cost: u64,
    /// Go's `latency`: the last `SigReq` round trip as of this instant
    /// (`debug.go:84-86`), which is a different number from `cost`.
    pub latency: Option<Duration>,
    pub up_for: Duration,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Bytes in the last whole sample window, on Go's own 1 s tick.
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub last_error: Option<String>,
    /// When `last_error` happened; `getPeers` prints its age.
    pub err_at: Option<Instant>,
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
    /// Stop redialling a configured peer, and — unlike Go, which also closes
    /// the connection (`links.remove`, `link.go:433-438`) — leave the live link
    /// alone. Slice 5's decision; `node_loop` pins it and Slice 9 owns revisiting
    /// it.
    Drop {
        uri: String,
        sintf: String,
        respond: Option<oneshot::Sender<Result<(), LinkError>>>,
    },
    /// A listener finished handshaking an inbound link. `uri` names it the way
    /// Go's `getPeers` does — the accepted socket's own peer address, in the
    /// listener's scheme — because an inbound row is a row like any other and
    /// needs a key of its own. `None` means the transport could not name the
    /// peer at all, which leaves the link served but unlisted, exactly as a link
    /// that never entered Go's `_links` map does.
    Accept { conn: AnyConn, uri: Option<String> },
    /// Queue a session payload for `dest`. (Slice 12 adds the IPv6-keyed
    /// resolve-and-hold form that a TUN needs; this is the one an app that
    /// already knows a node key wants.)
    Send { dest: [u8; 32], bytes: Vec<u8> },
    /// Answer with the node's whole readable state, then carry on.
    Report { respond: oneshot::Sender<Snapshot> },
    /// Ask a remote node something over an E2E session and wait for the answer.
    ///
    /// Go's four remote commands (`core/api.go:240-259` registering
    /// `getNodeInfo` and the three `debug_remoteGet*`) all do the same two
    /// things: send a request addressed to a node key through `PacketConn
    /// .WriteTo`, and block on a channel with a 6 s timer. The reply is matched
    /// by the node that sent it, which is why this is a command and not a call:
    /// only this task may read `proto_inbox`, and the answer arrives on a later
    /// tick, not inside this await.
    Remote {
        key: [u8; 32],
        what: RemoteQuery,
        respond: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    /// Answer `getTun`: the device's name and MTU, or `None` when the node has
    /// no TUN.
    ///
    /// A command rather than a method, for the same reason everything else here
    /// is: the device is a field on `Node`, so only the task running `Node::run`
    /// may read it.
    Tun {
        respond: oneshot::Sender<Option<(String, u16)>>,
    },
    /// Leave the loop after the current slice.
    Quit,
}

/// Which remote question to ask, and the dispatch byte that carries it.
///
/// The wire values are the library's (`src/proto.rs`): a `nodeinfo` request is
/// `[PROTO_NODEINFO_REQ]`, a debug request is `[PROTO_DEBUG, subtype]`. Go's
/// four admin commands are one nodeinfo request and three debug subtypes
/// (`core/proto.go:19-25`), so this is the same split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteQuery {
    /// `getNodeInfo`: the peer's advertised nodeinfo, verbatim JSON.
    NodeInfo,
    /// `debug_remoteGetSelf`: `{"key": hex, "routing_entries": "<n>"}`.
    SelfInfo,
    /// `debug_remoteGetPeers`: `{"keys": [hex, …]}`.
    Peers,
    /// `debug_remoteGetTree`: `{"keys": [hex, …]}`.
    Tree,
}

impl RemoteQuery {
    /// The protocol dispatch byte, for matching an answer to its question.
    pub fn answer_tag(self) -> (u8, Option<u8>) {
        use roots::proto::*;
        match self {
            RemoteQuery::NodeInfo => (PROTO_NODEINFO_RES, None),
            RemoteQuery::SelfInfo => (PROTO_DEBUG, Some(DEBUG_GETSELF_RES)),
            RemoteQuery::Peers => (PROTO_DEBUG, Some(DEBUG_GETPEERS_RES)),
            RemoteQuery::Tree => (PROTO_DEBUG, Some(DEBUG_GETTREE_RES)),
        }
    }
}

/// How long a remote question waits before it is a failure.
///
/// Go uses `time.After(6 * time.Second)` in all four handlers
/// (`nodeinfo.go:164-172`, `proto.go:281-285`, `:329-333`, `:373-377`) while the
/// bookkeeping underneath it expires at one minute. Six seconds is the operator's
/// wait, so it is the number that goes in the error.
pub const REMOTE_TIMEOUT: Duration = Duration::from_secs(6);

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
    /// Remote questions waiting for an answer.
    ///
    /// Go keeps three maps for the debug queries plus one for nodeinfo
    /// (`core/proto.go:44-49`, `core/nodeinfo.go:18-22`), each entry holding a
    /// callback and a one-minute expiry. One list keyed by node and question is
    /// the same thing without the repetition; the wait is [`REMOTE_TIMEOUT`]
    /// because that is the number the operator is told about.
    pending: Vec<PendingRemote>,
    /// The TUN bridge, when `IfName` configured one.
    ///
    /// A field rather than a task, and that is the whole design: the device reads
    /// the session inbox and calls `send_or_resolve`, both of which want
    /// `&mut Router` and `&mut LinkSet`. Those are single-owner in this client
    /// (`AGENTS.md`, "lib/client boundary"), so a TUN in its own task would need a
    /// lock over the one thing here that must not have one.
    tun: Option<crate::tun::Device>,
}

/// One outstanding remote question, waiting for a node to answer it.
struct PendingRemote {
    key: [u8; 32],
    what: RemoteQuery,
    asked_at: Instant,
    respond: oneshot::Sender<Result<Vec<u8>, String>>,
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
            pending: Vec::new(),
            tun: None,
        };
        let sender = node.tx.clone();
        (node, sender)
    }

    /// Attach a TUN bridge, which is how a config's `IfName` becomes a real
    /// interface.
    ///
    /// Called once, before [`Node::run`], because opening the device needs
    /// `CAP_NET_ADMIN` and a failure there is the operator's answer about it —
    /// a node that starts with no TUN and reports `enabled: false` is
    /// indistinguishable from one whose TUN silently dropped every packet.
    ///
    /// `local` is this node's own mesh address, which is what the device is
    /// addressed as: the kernel routes a packet for it here, and the mesh finds a
    /// path for it by the same key.
    ///
    /// Which packets the device forwards is not a parameter. It is the mesh range
    /// `0200::/7` (`tun.rs`, `Device::wants`), which is the one rule that holds
    /// for every node: it covers every peer address *and* every routed subnet
    /// prefix, and it needs no configuration that Go's own config does not have.
    pub async fn open_tun(
        &mut self,
        ifname: &str,
        local: roots::address::Address,
        mtu: u16,
    ) -> Result<(), roots::Error> {
        let device = crate::tun::open(ifname, local, crate::tun::supported_mtu(mtu)).await?;
        eprintln!(
            "TUN {} up with {} (mtu {})",
            device.name(),
            local,
            device.mtu()
        );
        self.tun = Some(device);
        Ok(())
    }

    /// Read the router and the link set from inside the node task, which is the
    /// only place either may be read while the node runs.
    fn snapshot(&self) -> Snapshot {
        let known = self.router.link_peers();
        let peers = self
            .peers
            .entries()
            .iter()
            .map(|e| {
                // The row's own link, asked by identity. A [`roots::LinkId`] is
                // the only thing that tells two connections to one node apart,
                // and Go joins its rows the same way — by connection, not by
                // key (`core/api.go:85-103`). So a node that dialled us while we
                // dialled it produces two rows, each reporting its own
                // direction, counters and round trip.
                //
                // Everything the set and the router have to say about the row is
                // gated on that one answer, so a row never reports the key, the
                // direction or the counters of a link it no longer holds.
                let live = e
                    .live
                    .and_then(|(id, key)| self.links.stats(id).map(|s| (id, key, s)));
                let router = live
                    .as_ref()
                    .and_then(|(id, _, _)| known.iter().find(|p| p.id == *id));
                let (port, priority, cost, latency) = router
                    .map(|p| (p.port, p.priority, p.lag_ms.max(1) as u64, p.latency))
                    .unwrap_or((0, 0, 0, None));
                PeerRow {
                    // Go reports the *link* URI, not the operator's: `PeerInfo.URI
                    // = info.uri` (`core/api.go:83`) and that map key went through
                    // `urlForLinkInfo` (`link.go:766-769`), which blanks the query.
                    // So `?password=` is never echoed back over the admin socket —
                    // which matters, because it is a secret.
                    uri: link_id(&e.uri),
                    sintf: e.sintf.clone(),
                    key: live.as_ref().map(|(_, k, _)| *k),
                    up: live.is_some(),
                    // Go's is the row's link type, not the connection's
                    // (`api.go:87`), and only while the row has a connection.
                    inbound: live.is_some() && e.kind == LinkKind::Incoming,
                    port,
                    priority,
                    cost,
                    latency,
                    up_for: live.as_ref().map(|(_, _, s)| s.up).unwrap_or_default(),
                    rx_bytes: live.as_ref().map(|(_, _, s)| s.rx_bytes).unwrap_or(0),
                    tx_bytes: live.as_ref().map(|(_, _, s)| s.tx_bytes).unwrap_or(0),
                    rx_rate: live.as_ref().map(|(_, _, s)| s.rx_rate).unwrap_or(0),
                    tx_rate: live.as_ref().map(|(_, _, s)| s.tx_rate).unwrap_or(0),
                    last_error: e.last_error.clone(),
                    err_at: e.err_at,
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
            // Byte rates are differenced on Go's own 1 s tick (`link.go:106-129`).
            // The set keeps the phase, so calling this every pass is how a 50 ms
            // node loop still reports a 1 s measurement.
            self.links.update_rates();
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
            // Answers to remote questions, then the ones nobody answered. Both
            // are read here because this is the only task that may read
            // `proto_inbox`: it fills during the serve slice above.
            self.settle_remote();
            self.pump_tun().await;
        }
        Ok(())
    }

    /// Move packets both ways between the TUN and the mesh.
    ///
    /// Three steps, in this order, and the order is the design:
    ///
    /// 1. **Session inbox to the device.** `serve` has just filled the inbox, and
    ///    a session payload is a whole IP packet, so it goes straight out. This is
    ///    Go's `ipv6rwc` handing a packet to the TUN (`ipv6rwc.go:174-199`).
    /// 2. **Device to the mesh.** Read what the kernel routed at us and hand it to
    ///    `send_or_resolve`, which resolves the destination, queues the packet
    ///    while the lookup runs, and flushes it on the notify. A queued packet is
    ///    not a lost one — that is the whole reason Slice 12 exists.
    /// 3. **Back out of the device.** `flush` runs last so a device buffer that
    ///    will not take the write does not also stop the mesh side being pumped.
    ///
    /// A device with no traffic costs two non-blocking reads, which is why this is
    /// inline rather than behind a flag.
    async fn pump_tun(&mut self) {
        let Some(device) = self.tun.as_mut() else {
            return;
        };
        // 1. The mesh's packets to the kernel. Every session payload is a packet:
        // the session layer carries whole IP datagrams and nothing else
        // (`session.rs`), so there is no framing to unwrap and no way to tell a
        // packet from another payload — which is exactly why the device is only
        // enabled when the node is a router for IP.
        for (_, packet) in self.router.inbox.drain(..) {
            device.deliver(packet);
        }
        // 2. The kernel's packets to the mesh. The lookup leaves on the first
        // live link, which is a choice rather than a route: `send_or_resolve`
        // only needs *a* link to start the DHT query on, and the pathfinder picks
        // the one the traffic should go out by (`driver.rs`, `pathfind.rs`).
        let via = self.links.ids().first().copied();
        // `send_or_resolve` is `&mut self.router` and `&mut self.links` while
        // `device` borrows `self`, so the borrow has to be split by hand.
        let Node {
            router, links, tun, ..
        } = self;
        if let (Some(tun), Some(via)) = (tun.as_mut(), via)
            && let Err(e) = tun.pump(router, links, Some(via)).await
            && !e.is_link()
        {
            // A dead device is not a dead node: drop it and keep serving links.
            eprintln!("tun: {e}");
            self.tun = None;
            return;
        }
        // 3. Whatever the mesh produced, out to the kernel. A failed write means
        // the device is gone — it was deleted, or its namespace went away — and it
        // is dropped for the same reason a failed read drops it: an outbox nobody
        // drains grows without bound, and a node with no TUN reports
        // `enabled: false` rather than pretending.
        if let Some(tun) = self.tun.as_mut()
            && let Err(e) = tun.flush().await
        {
            eprintln!("tun: {e}");
            self.tun = None;
        }
    }

    /// Match whatever arrived in `proto_inbox` against the questions still
    /// waiting, and fail the ones that have waited out Go's 6 s.
    fn settle_remote(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut still: Vec<PendingRemote> = Vec::new();
        for q in std::mem::take(&mut self.pending) {
            if now.duration_since(q.asked_at) >= REMOTE_TIMEOUT {
                // Go's `time.After(6 * time.Second)` arm, with its own wording
                // (`nodeinfo.go:169` and `proto.go:284`, `:332`, `:376`).
                let msg = match q.what {
                    RemoteQuery::NodeInfo => "timed out waiting for response",
                    _ => "timeout",
                };
                let _ = q.respond.send(Err(msg.to_string()));
                continue;
            }
            let (tag, sub) = q.what.answer_tag();
            let answer = self
                .router
                .proto_inbox
                .iter()
                .position(|(from, bytes)| *from == q.key && Self::is_answer(bytes, tag, sub))
                .map(|at| {
                    let (_, bytes) = self.router.proto_inbox.remove(at);
                    bytes
                });
            match answer {
                Some(bytes) => {
                    let _ = q.respond.send(Ok(Self::answer_body(bytes, tag, sub)));
                }
                None => still.push(q),
            }
        }
        self.pending = still;
    }

    /// Does this inbound proto payload answer the question `tag`/`sub` names?
    ///
    /// A nodeinfo answer is `[PROTO_NODEINFO_RES, …json]`. A debug answer is
    /// `[PROTO_DEBUG, subtype, …]`, and the library re-adds the dispatch byte
    /// when it files the reply (`src/proto.rs`), so both bytes are present.
    fn is_answer(bytes: &[u8], tag: u8, sub: Option<u8>) -> bool {
        match sub {
            None => bytes.first() == Some(&tag),
            Some(sub) => bytes.len() >= 2 && bytes[0] == tag && bytes[1] == sub,
        }
    }

    /// Strip the dispatch bytes, leaving the payload the handler marshals.
    ///
    /// Go's handlers get the body without them: `_handleGetSelfResponse(key,
    /// bs[1:])` after `handleProto` has already peeled the proto byte
    /// (`proto.go:87`, `:91`, `:95`), and `json.Unmarshal` then sees a bare
    /// object. So ours must not, or the admin body would nest the dispatch byte
    /// inside the JSON.
    fn answer_body(bytes: Vec<u8>, tag: u8, sub: Option<u8>) -> Vec<u8> {
        let n = if sub.is_some() { 2 } else { 1 };
        debug_assert_eq!(bytes.first(), Some(&tag));
        bytes.into_iter().skip(n).collect()
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
                // Go's `links.remove` cancels the redial context **and** closes
                // the live connection (`core/link.go:433-438`), so the row
                // disappears from `getPeers` with the link. Slice 5 kept ours
                // open on the strength of the comment at `core/api.go:207-211`
                // ("the peer is not disconnected immediately"), which reading
                // Go disproves: the comment describes nothing that happens.
                // Parity is the product, so this now closes the link, and the
                // row set that results is what Go's would be.
                //
                // The id has to be taken before the row goes, because the row is
                // what holds it. Asking afterwards would always answer "no
                // link" and quietly leave the socket open.
                let id = self.peers.live_id(&uri, &sintf);
                let outcome = self.peers.remove(&uri, &sintf);
                if outcome.is_ok()
                    && let Some(id) = id
                {
                    // Take the link out of the set and drop the `AnyConn` it
                    // returns, which closes the socket. This is not Go's
                    // nil-context panic on an inbound row's URI (`link.go:536-543`
                    // builds an inbound link without a context, and `:434`
                    // dereferences it): we hold the id either way, so there is
                    // nothing to panic on.
                    if let Some(conn) = self.links.remove(id) {
                        drop(conn);
                    }
                    self.router.forget_link(id);
                }
                match (respond, &outcome) {
                    (Some(respond), _) => {
                        let _ = respond.send(outcome);
                    }
                    (None, Err(e)) => eprintln!("peer {uri}: {e}"),
                    (None, Ok(())) => {}
                }
            }
            Cmd::Accept { conn, uri } => {
                let mut conn = conn;
                // Go's listener goroutine checks the row before it does anything
                // else with the link, and drops the connection when the row is
                // busy (`link.go:529-541`).
                if uri.as_deref().is_some_and(|uri| self.peers.busy(uri)) {
                    return;
                }
                let (peer, id) = (conn.remote_key, conn.id);
                if let Err(e) = self.router.register(&mut conn, peer, id).await {
                    eprintln!("inbound link dropped: {e}");
                    return;
                }
                if let Some(uri) = uri {
                    self.peers.accept(&uri, &conn);
                }
                self.links.add(conn);
            }
            Cmd::Report { respond } => {
                let _ = respond.send(self.snapshot());
            }
            Cmd::Send { dest, bytes } => self.outbox.push((dest, bytes)),
            Cmd::Tun { respond } => {
                let answer = self.tun.as_ref().map(|t| (t.name().to_string(), t.mtu()));
                let _ = respond.send(answer);
            }
            Cmd::Remote { key, what, respond } => {
                // The request goes out addressed to a node key, so the
                // pathfinder picks the next hop — the same route any other
                // payload to that node takes. Go reaches the same place through
                // `PacketConn.WriteTo` (`core/proto.go:101`,
                // `core/nodeinfo.go:114`), which is what makes the answer come
                // back from the node asked rather than from whichever link
                // happened to be first.
                use roots::proto::*;
                let sent = match what {
                    RemoteQuery::NodeInfo => {
                        self.router.request_nodeinfo(&mut self.links, key).await
                    }
                    other => {
                        let sub = match other {
                            RemoteQuery::SelfInfo => DEBUG_GETSELF_REQ,
                            RemoteQuery::Peers => DEBUG_GETPEERS_REQ,
                            _ => DEBUG_GETTREE_REQ,
                        };
                        self.router.request_debug(&mut self.links, key, sub).await
                    }
                };
                match sent {
                    Ok(()) => self.pending.push(PendingRemote {
                        key,
                        what,
                        asked_at: Instant::now(),
                        respond,
                    }),
                    // A send that fails has not started a clock, so the caller
                    // is told now instead of waiting out a timeout for an answer
                    // that can never arrive. Go's `WriteTo` discards this too
                    // (`core/nodeinfo.go:114`, `_ =`), because the session
                    // layer buffers the request; ours reports it because the
                    // admin socket has nowhere to hide it.
                    Err(e) => {
                        let _ = respond.send(Err(e.to_string()));
                    }
                }
            }
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
        let (peer, id) = (conn.remote_key, conn.id);
        if let Err(e) = self.router.register(&mut conn, peer, id).await {
            eprintln!("dial {uri}: {e}");
            self.peers.mark_failed(token, &e.to_string());
            return;
        }
        if self.peers.mark_live(token, &conn) {
            self.links.add(conn);
        }
        // Otherwise the peer was dropped while we were dialling, and dropping the
        // connection here is Go's "if a peering has come up in this time, abort
        // this one" (`link.go:366-373`).
    }
}
