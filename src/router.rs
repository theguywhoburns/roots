//! Spanning-tree router: owns all protocol state and drives the link
//! set (`register` once per link, `serve`/`serve_links` per slice).
//! The tree protocol itself (`SigReq`/`SigRes`/`Announce`, parent
//! selection) lives in `src/tree.rs`; pathfinder, sessions, blooms and
//! nodeinfo/debug are sibling `impl Router` extensions, mirroring how
//! `ironwood/network/router.go` composes.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use crate::address::KEY_LEN;
use crate::bloom::BloomFilter;
use crate::error::Error;
use crate::frame::FrameType;
use crate::link::{Link, LinkSet};
use crate::pathfind::NotifyInfo;
use crate::session::Session;
use crate::tree::{Announce, Info, SigReq, SigRes};

/// Router maintenance tick (Go: 1s).
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);
/// Unknown-link latency sentinel (Go: `routerUnknownLatency`).
pub const UNKNOWN_LATENCY: Duration = Duration::from_millis(u32::MAX as u64);

pub(crate) struct PeerState {
    /// Our local port number for this link (we number from 1).
    pub(crate) port: u64,
    pub(crate) req: SigReq,
    pub(crate) responded: bool,
    pub(crate) lag: Duration,
    pub(crate) sent_at: Option<Instant>,
    /// Link priority from the handshake (lowest wins among same-key links;
    /// single link per key for now — used when the conn map lands).
    pub(crate) prio: u8,
    /// Connection order (oldest wins final tiebreaks).
    pub(crate) order: u64,
}

/// Spanning-tree router: all protocol state in one place, driven link
/// by link through a [`LinkSet`] (`register` once per link, `serve` /
/// `serve_links` per slice). Peer I/O stays at this layer; the tree
/// rules live in `src/tree.rs`.
pub struct Router {
    pub(crate) key: SigningKey,
    pub(crate) pubkey: [u8; KEY_LEN],
    pub(crate) peers: HashMap<[u8; KEY_LEN], PeerState>,
    pub(crate) infos: HashMap<[u8; KEY_LEN], Info>,
    pub(crate) info_deadlines: HashMap<[u8; KEY_LEN], Instant>,
    pub(crate) responses: HashMap<[u8; KEY_LEN], SigRes>,
    pub(crate) sent: HashMap<[u8; KEY_LEN], HashSet<[u8; KEY_LEN]>>,
    pub(crate) next_port: u64,
    pub(crate) refresh: bool,
    pub(crate) do_root1: bool,
    pub(crate) do_root2: bool,
    pub(crate) self_refresh_at: Option<Instant>,
    // --- pathfinder (ironwood/network/pathfinder.go) ---
    pub(crate) paths: HashMap<[u8; KEY_LEN], crate::pathfind::PathEntry>,
    pub(crate) rumors: HashMap<[u8; KEY_LEN], crate::pathfind::RumorEntry>,
    pub(crate) notify_info: NotifyInfo,
    // --- blooms (ironwood/network/bloomfilter.go) ---
    pub(crate) bloom_send: HashMap<[u8; KEY_LEN], BloomFilter>,
    pub(crate) bloom_recv: HashMap<[u8; KEY_LEN], BloomFilter>,
    pub(crate) bloom_on_tree: HashMap<[u8; KEY_LEN], bool>,
    pub(crate) bloom_dirty: HashMap<[u8; KEY_LEN], bool>,
    // --- sessions (ironwood/encrypted/session.go) ---
    pub(crate) sessions: HashMap<[u8; KEY_LEN], (Session, Instant)>,
    pub(crate) session_bufs: HashMap<[u8; KEY_LEN], crate::session::SessionBuf>,
    pub(crate) peer_order: u64,
    /// App payloads that failed mid-write on a dead link, retried on the
    /// next link (at-least-once across reconnects; duplicates possible).
    pub(crate) resend: Vec<([u8; KEY_LEN], Vec<u8>)>,
    /// Delivered session payloads: `(from_key, bytes)`.
    pub inbox: Vec<([u8; KEY_LEN], Vec<u8>)>,
    /// Our advertised nodeinfo (raw JSON; see `src/proto.rs`).
    pub(crate) nodeinfo: Vec<u8>,
    /// Delivered session-protocol responses: `(from_key, proto_bytes)`
    /// where `proto_bytes` starts with the `PROTO_*` dispatch byte.
    pub proto_inbox: Vec<([u8; KEY_LEN], Vec<u8>)>,
    /// Frames received per type (for diagnostics).
    pub frames: [u64; 10],
    pub announces_sent: u64,
    pub announces_recv: u64,
}

impl Router {
    pub fn new(key: SigningKey) -> Self {
        let pubkey = key.verifying_key().to_bytes();
        Self {
            key,
            pubkey,
            peers: HashMap::new(),
            infos: HashMap::new(),
            info_deadlines: HashMap::new(),
            responses: HashMap::new(),
            sent: HashMap::new(),
            next_port: 1,
            refresh: false,
            do_root1: false,
            do_root2: true,
            self_refresh_at: None,
            paths: HashMap::new(),
            rumors: HashMap::new(),
            notify_info: NotifyInfo {
                seq: 0,
                path: Vec::new(),
                sig: [0u8; 64],
            },
            bloom_send: HashMap::new(),
            bloom_recv: HashMap::new(),
            bloom_on_tree: HashMap::new(),
            bloom_dirty: HashMap::new(),
            sessions: HashMap::new(),
            session_bufs: HashMap::new(),
            peer_order: 0,
            resend: Vec::new(),
            inbox: Vec::new(),
            nodeinfo: crate::proto::NODEINFO_DEFAULT.to_vec(),
            proto_inbox: Vec::new(),
            frames: [0; 10],
            announces_sent: 0,
            announces_recv: 0,
        }
    }

    pub fn pubkey(&self) -> [u8; KEY_LEN] {
        self.pubkey
    }

    pub fn parent(&self) -> Option<[u8; KEY_LEN]> {
        self.infos.get(&self.pubkey).map(|i| i.parent)
    }

    pub fn root_and_depth(&self) -> Option<([u8; KEY_LEN], usize)> {
        let mut next = self.pubkey;
        let mut depth = 0;
        loop {
            let info = self.infos.get(&next)?;
            if info.parent == next {
                return Some((next, depth));
            }
            depth += 1;
            if depth > 1024 {
                return None;
            }
            next = info.parent;
        }
    }

    pub fn known_nodes(&self) -> usize {
        self.infos.len()
    }

    /// Debug snapshot of tree + path + link state. Returns text instead of
    /// printing: the lib never writes to stderr; binaries decide (gated
    /// behind `ROOTS_DBG_DUMP` in `src/main.rs`).
    pub fn dump(&self) -> String {
        let mut out = String::new();
        let mut peers: Vec<_> = self.peers.keys().collect();
        peers.sort();
        for k in peers {
            let p = &self.peers[k];
            out.push_str(&format!(
                "PEER key={} prio={} order={}\n",
                hex::encode(k),
                p.prio,
                p.order
            ));
        }
        let mut keys: Vec<_> = self.infos.keys().collect();
        keys.sort();
        for k in keys {
            let i = &self.infos[k];
            out.push_str(&format!(
                "INFO key={} parent={} seq={} port={}\n",
                hex::encode(k),
                hex::encode(i.parent),
                i.res.req.seq,
                i.res.port
            ));
        }
        let mut paths: Vec<_> = self.paths.keys().collect();
        paths.sort();
        for k in paths {
            let e = &self.paths[k];
            out.push_str(&format!(
                "PATH key={} path={:?} seq={}\n",
                hex::encode(k),
                e.path,
                e.seq
            ));
        }
        out.push_str(&format!("SELF coords={:?}\n", self.root_path()));
        out
    }

    /// True when we hold a live source route to `key` (for diagnostics).
    pub fn has_path(&self, key: &[u8; KEY_LEN]) -> bool {
        self.paths.contains_key(key)
    }

    /// True when an E2E session exists for `key` (for diagnostics).
    pub fn has_session(&self, key: &[u8; KEY_LEN]) -> bool {
        self.sessions.contains_key(key)
    }

    /// Learned source route + notify seq for `key` (for diagnostics).
    pub fn path_details(&self, key: &[u8; KEY_LEN]) -> Option<(Vec<u64>, u64)> {
        self.paths.get(key).map(|e| (e.path.clone(), e.seq))
    }

    /// Register a peer after the link handshake: open SigReq, bloom, and
    /// replay of already-sent announces (Go `addPeer`). Call ONCE per link
    /// (not per serve slice): the peer answers every SigReq and replays
    /// are sent-map-gated, so repeats look like a reconnect storm.
    pub async fn register(
        &mut self,
        conn: &mut dyn Link,
        peer_key: [u8; KEY_LEN],
    ) -> Result<(), Error> {
        // Reuse the link port for a known key (Go keeps one port per key
        // across reconnects); only brand-new keys allocate.
        let port = self
            .peers
            .get(&peer_key)
            .map(|p| p.port)
            .unwrap_or_else(|| {
                let q = self.next_port;
                self.next_port += 1;
                q
            });
        let order = self.peer_order;
        self.peer_order += 1;
        // Reuse the open request for a known key (Go re-sends the stored
        // req on re-add; minting a fresh req per serve call looks like a
        // reconnect storm and gets answered as one).
        let req = self
            .peers
            .get(&peer_key)
            .map(|p| p.req)
            .unwrap_or_else(|| self.new_req());
        // Keep the RTT estimate across reconnects; everything else is fresh
        // per link (Go resets per-link state the same way).
        let lag = self
            .peers
            .get(&peer_key)
            .map(|p| p.lag)
            .unwrap_or(UNKNOWN_LATENCY);
        let peer = PeerState {
            port,
            req,
            responded: false,
            lag,
            sent_at: Some(Instant::now()),
            prio: conn.priority(),
            order,
        };
        // One registration per link (callers register once, then serve in
        // slices): open SigReq, bloom, and replay of already-sent announces
        // for a known key (Go `addPeer` replays to new links the same way).
        self.peers.insert(peer_key, peer);
        self.sent.entry(peer_key).or_default();
        self.bloom_add_peer(peer_key);
        // Advertise our (initially empty) bloom immediately, like Go.
        let bloom_bytes = self
            .bloom_send
            .get(&peer_key)
            .map(|b| b.encode())
            .unwrap_or_default();
        conn.write_frame(FrameType::BloomFilter, &bloom_bytes)
            .await?;
        let mut out = Vec::new();
        req.encode(&mut out);
        conn.write_frame(FrameType::SigReq, &out).await?;
        // Replay anything already announced to this key over older links.
        let replay: Vec<Announce> = self
            .sent
            .get(&peer_key)
            .map(|s| {
                s.iter()
                    .filter_map(|k| self.infos.get(k).map(|i| i.announce(*k)))
                    .collect()
            })
            .unwrap_or_default();
        for ann in replay {
            let mut buf = Vec::new();
            ann.encode(&mut buf);
            conn.write_frame(FrameType::Announce, &buf).await?;
            self.announces_sent += 1;
        }
        Ok(())
    }

    /// Resolve an IPv6 address to its full node key: look up the partial
    /// key until a signed path-notify names a key with this address.
    /// Handles both node addresses (`02…`) and routed subnets (`03…`, resolved
    /// to the owning node). Returns the key (also usable directly for
    /// [`Router::session_send`] via the `serve` outbox). Times out with
    /// [`Error::Timeout`].
    pub async fn resolve(
        &mut self,
        conn: &mut dyn Link,
        conn_peer: [u8; KEY_LEN],
        addr: &crate::address::Address,
        timeout: Duration,
    ) -> Result<[u8; KEY_LEN], Error> {
        let mut links = LinkSet::single(conn_peer, conn);
        let links = &mut links;
        let partial = crate::address::lookup_key_for_addr(addr);
        let end = tokio::time::Instant::now() + timeout;
        let mut last_maintain = tokio::time::Instant::now();
        while tokio::time::Instant::now() < end {
            // Via the rumor path (creates the pending entry that lets us
            // accept the arriving notify), like Go's `SendLookup`.
            self.rumor_lookup(links, conn_peer, partial).await?;
            // Keep the tree alive while resolving (same tick as serve).
            let now = tokio::time::Instant::now();
            if now.duration_since(last_maintain) >= MAINTENANCE_INTERVAL {
                last_maintain = now;
                self.maintain(links, conn_peer).await?;
            }
            let remaining = end.saturating_duration_since(tokio::time::Instant::now());
            let wait = remaining.min(Duration::from_secs(2));
            let frame = match links.get(&conn_peer) {
                Some(link) => tokio::time::timeout(wait, link.read_frame()).await,
                None => continue,
            };
            match frame {
                Ok(Ok((ftype, payload))) => {
                    self.frames[ftype as usize] += 1;
                    self.dispatch_frame(links, conn_peer, ftype, &payload)
                        .await?;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {}
            }
            let want = addr.0;
            let want_subnet = addr.0[0] == crate::address::NODE_PREFIX | crate::address::SUBNET_BIT;
            if let Some(k) = self
                .paths
                .keys()
                .find(|k| {
                    crate::address::addr_for_key(k).0 == want
                        || (want_subnet
                            && crate::address::subnet_for_key(k).0
                                == want[..crate::address::SUBNET_LEN])
                })
                .copied()
            {
                return Ok(k);
            }
        }
        Err(Error::Timeout)
    }

    /// One maintenance tick: expire, fix parent, send announces.
    pub async fn maintain(
        &mut self,
        links: &mut LinkSet<'_>,
        peer_key: [u8; KEY_LEN],
    ) -> Result<(), Error> {
        self.expire();
        self.fix(links, peer_key).await?;
        self.send_announces(links, peer_key).await?;
        self.bloom_maintenance(links).await?;
        self.expire_ephemeral();
        // Re-drive lookups for still-pending rumors (a lookup sent before
        // blooms converged is dropped, not queued — Go relies on the app
        // to retransmit; without an app layer we retry here, throttled).
        // Resolved when some path shares the rumor's transformed key.
        let pending: Vec<[u8; KEY_LEN]> = self
            .rumors
            .iter()
            .filter(|(x, r)| {
                r.pending.is_some() && !self.paths.keys().any(|k| crate::bloom::xkey(k) == **x)
            })
            .map(|(_, r)| r.dest)
            .collect();
        for dest in pending {
            self.rumor_lookup(links, peer_key, dest).await?;
        }
        Ok(())
    }

    /// Drop expired paths, rumors, session buffers, and idle sessions.
    pub(crate) fn expire_ephemeral(&mut self) {
        let now = Instant::now();
        self.paths.retain(|_, e| e.deadline > now);
        self.rumors.retain(|_, r| r.deadline > now);
        self.session_bufs.retain(|_, b| b.deadline > now);
        self.sessions
            .retain(|_, (_, active)| *active + crate::session::SESSION_TIMEOUT > now);
    }

    /// Handle one inbound frame: router protocol plus a keepalive reply for
    /// every non-keepalive type (Go `peerMonitor` semantics).
    pub(crate) async fn dispatch_frame(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        ftype: FrameType,
        payload: &[u8],
    ) -> Result<(), Error> {
        match ftype {
            FrameType::KeepAlive | FrameType::Dummy => {}
            FrameType::SigReq => {
                if let Ok((req, n)) = SigReq::decode(payload)
                    && n == payload.len()
                {
                    self.handle_request(links, conn_peer, req).await?;
                }
                links.write(conn_peer, FrameType::KeepAlive, &[]).await?;
            }
            FrameType::SigRes => {
                if let Ok((res, n)) = SigRes::decode(payload)
                    && n == payload.len()
                    && res.check(&self.pubkey, &conn_peer)
                {
                    self.handle_response(conn_peer, res);
                }
                links.write(conn_peer, FrameType::KeepAlive, &[]).await?;
            }
            FrameType::Announce => {
                if let Ok(ann) = Announce::decode_exact(payload)
                    && ann.check()
                {
                    let reply = self.handle_announce(links, conn_peer, &ann);
                    if let Some(better) = reply {
                        let mut buf = Vec::new();
                        better.encode(&mut buf);
                        links.write(conn_peer, FrameType::Announce, &buf).await?;
                        self.announces_sent += 1;
                    }
                }
                links.write(conn_peer, FrameType::KeepAlive, &[]).await?;
            }
            FrameType::BloomFilter => {
                let _ = self.bloom_handle(conn_peer, payload);
                links.write(conn_peer, FrameType::KeepAlive, &[]).await?;
            }
            FrameType::PathLookup => {
                if let Ok(lookup) = crate::pathfind::PathLookup::decode_exact(payload) {
                    self.handle_lookup(links, conn_peer, conn_peer, &lookup)
                        .await?;
                }
                links.write(conn_peer, FrameType::KeepAlive, &[]).await?;
            }
            FrameType::PathNotify => {
                if let Ok(notify) = crate::pathfind::PathNotify::decode_exact(payload)
                    && notify.check()
                {
                    self.handle_notify(links, conn_peer, &notify).await?;
                }
                links.write(conn_peer, FrameType::KeepAlive, &[]).await?;
            }
            FrameType::PathBroken => {
                if let Ok(broken) = crate::pathfind::PathBroken::decode_exact(payload) {
                    self.handle_broken(links, conn_peer, &broken).await?;
                }
                links.write(conn_peer, FrameType::KeepAlive, &[]).await?;
            }
            FrameType::Traffic => {
                if let Ok(tr) = crate::traffic::Traffic::decode(payload) {
                    self.handle_inbound_traffic(links, conn_peer, &tr).await?;
                }
                links.write(conn_peer, FrameType::KeepAlive, &[]).await?;
            }
        }
        Ok(())
    }

    /// Serve one peer link: handshake done and peer registered (see
    /// [`Router::register`], called once per link before slicing serve).
    /// Runs the frame loop with keepalive replies + router protocol.
    /// `hold_for = None` serves until the link drops; `Some` bounds
    /// demo/test runs.
    /// `(dest, payload)` pairs in `outgoing` are sent as session payloads
    /// (buffered behind lookup + handshake automatically). Payloads that
    /// fail mid-write are re-queued into `resend` for the next link.
    pub async fn serve(
        &mut self,
        conn: &mut dyn Link,
        peer_key: [u8; KEY_LEN],
        hold_for: Option<Duration>,
        outgoing: &mut Vec<([u8; KEY_LEN], Vec<u8>)>,
    ) -> Result<(), Error> {
        self.serve_links(&mut LinkSet::single(peer_key, conn), hold_for, outgoing)
            .await
    }

    /// Serve every link in the set through one router: per-link maintain,
    /// shared session outbox, frames dispatched with their arrival peer.
    /// Single-link `serve` is this with a one-entry set; multi-peer apps
    /// register each link once, then slice this.
    pub async fn serve_links(
        &mut self,
        links: &mut LinkSet<'_>,
        hold_for: Option<Duration>,
        outgoing: &mut Vec<([u8; KEY_LEN], Vec<u8>)>,
    ) -> Result<(), Error> {
        // Previously failed payloads go first (at-least-once across links).
        outgoing.splice(..0, std::mem::take(&mut self.resend));
        let end = hold_for.map(|h| tokio::time::Instant::now() + h);
        let mut last_maintain = tokio::time::Instant::now();
        for peer in links.peers() {
            self.maintain(links, peer).await?;
        }
        loop {
            let now = tokio::time::Instant::now();
            if let Some(end) = end
                && now >= end
            {
                break;
            }
            for (dest, msg) in std::mem::take(outgoing) {
                // Outbox sends are link-agnostic (pathfinder routes); the
                // first peer key only scopes per-link state refreshes.
                let peer = links.peers().into_iter().next().unwrap_or(self.pubkey);
                self.session_send(links, peer, dest, msg).await?;
            }
            if now.duration_since(last_maintain) >= MAINTENANCE_INTERVAL {
                last_maintain = now;
                for peer in links.peers() {
                    self.maintain(links, peer).await?;
                }
            }
            let timeout = end
                .map(|e| e.saturating_duration_since(now))
                .unwrap_or(MAINTENANCE_INTERVAL)
                .min(MAINTENANCE_INTERVAL);
            // Drain every link. A single link blocks for the whole budget
            // (exact old `serve` timing); several links take short slices
            // each so one quiet link never starves the rest.
            let slice = if links.peers().len() > 1 {
                timeout.min(Duration::from_millis(100))
            } else {
                timeout
            };
            for peer in links.peers() {
                let frame = match links.get(&peer) {
                    Some(link) => tokio::time::timeout(slice, link.read_frame()).await,
                    None => continue,
                };
                match frame {
                    Ok(Ok((ftype, payload))) => {
                        self.frames[ftype as usize] += 1;
                        self.dispatch_frame(links, peer, ftype, &payload).await?;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {}
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::LinkOptions;
    use crate::link::Tcp;

    #[tokio::test]
    async fn mixed_transport_links_share_one_router() {
        // Slice 10a: one Router drives a TCP link and a WS link (the WS
        // side type-erased through `AnyConn`) as `&mut dyn Link`. Tree
        // converges and a session opens over the TCP leg.
        use crate::link::AnyConn;

        let c_sk = SigningKey::from_bytes(&[0x40; 32]);
        let s1_sk = SigningKey::from_bytes(&[0x10; 32]);
        let s2_sk = SigningKey::from_bytes(&[0x20; 32]);
        let s1_pub = s1_sk.verifying_key().to_bytes();

        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let srv1 = tokio::spawn(async move {
            let (sock, _) = tcp_listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _) = crate::link::run_handshake(&mut sock, &s1_sk, &opts, true)
                .await
                .unwrap();
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                stream: sock,
            };
            let mut router = Router::new(s1_sk);
            router.register(&mut conn, key).await.unwrap();
            let _ = router
                .serve(
                    &mut conn,
                    key,
                    Some(Duration::from_secs(15)),
                    &mut Vec::new(),
                )
                .await;
        });
        let ws_listener = crate::ws::ws_listen("ws://127.0.0.1:0").await.unwrap();
        let ws_addr = ws_listener.local_addr().unwrap();
        let srv2 = tokio::spawn(async move {
            let mut conn = crate::ws::ws_accept(&ws_listener, &s2_sk, &LinkOptions::default())
                .await
                .unwrap();
            let key = conn.remote_key;
            let mut router = Router::new(s2_sk);
            router.register(&mut conn, key).await.unwrap();
            let _ = router
                .serve(
                    &mut conn,
                    key,
                    Some(Duration::from_secs(15)),
                    &mut Vec::new(),
                )
                .await;
        });

        let tcp_uri = format!("tcp://{tcp_addr}");
        let mut tcp_conn = crate::link::dial(&tcp_uri, &c_sk, &LinkOptions::default())
            .await
            .unwrap();
        let tcp_peer = tcp_conn.remote_key;
        let ws_uri = format!("ws://{ws_addr}");
        let ws_conn = crate::ws::ws_dial(&ws_uri, &c_sk, &LinkOptions::default())
            .await
            .unwrap();
        let ws_peer = ws_conn.remote_key;
        let mut ws_conn = AnyConn::new(ws_conn);

        let mut router = Router::new(c_sk);
        router.register(&mut tcp_conn, tcp_peer).await.unwrap();
        router.register(&mut ws_conn, ws_peer).await.unwrap();

        // One router serves both links through a single set (the 10b
        // shape); TCP stays concrete, WS arrives type-erased.
        let mut links = LinkSet::single(tcp_peer, &mut tcp_conn);
        links.add(ws_peer, &mut ws_conn);
        router
            .serve_links(&mut links, Some(Duration::from_secs(8)), &mut Vec::new())
            .await
            .unwrap();
        assert!(router.parent().is_some(), "converged over mixed links");
        assert!(router.known_nodes() >= 3, "learned both peers");

        // Full stack over the TCP leg through the same set interface.
        router
            .session_send(&mut links, tcp_peer, s1_pub, vec![0])
            .await
            .unwrap();
        let end = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < end {
            if router.has_session(&s1_pub) {
                break;
            }
            router.maintain(&mut links, tcp_peer).await.unwrap();
            router.maintain(&mut links, ws_peer).await.unwrap();
            for peer in [tcp_peer, ws_peer] {
                if let Ok(Ok((ftype, payload))) = tokio::time::timeout(
                    Duration::from_millis(100),
                    links.get(&peer).unwrap().read_frame(),
                )
                .await
                {
                    router
                        .dispatch_frame(&mut links, peer, ftype, &payload)
                        .await
                        .unwrap();
                }
            }
        }
        assert!(router.has_session(&s1_pub), "session over dyn TCP link");
        srv1.abort();
        srv2.abort();
    }

    #[tokio::test]
    async fn two_routers_converge_over_loopback() {
        // A dials B; both run routers for a beat. B should adopt A as parent
        // only if A is the lesser key... here just assert both learn each
        // other and stay consistent (no panics, infos exchanged).
        let a_sk = SigningKey::from_bytes(&[0x10; 32]);
        let b_sk = SigningKey::from_bytes(&[0x20; 32]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _) = crate::link::run_handshake(&mut sock, &b_sk, &opts, true)
                .await
                .unwrap();
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                stream: sock,
            };
            let mut router = Router::new(b_sk);
            // Either side may close first at the deadline; convergence is
            // what we assert below, not a clean shutdown.
            let mut no_out = Vec::new();
            router.register(&mut conn, key).await.unwrap();
            let _ = router
                .serve(
                    &mut conn,
                    key,
                    Some(Duration::from_millis(2600)),
                    &mut no_out,
                )
                .await;
            router
        });
        let uri = format!("tcp://{addr}");
        let mut conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        let mut router = Router::new(a_sk);
        let mut no_out = Vec::new();
        router.register(&mut conn, peer_key).await.unwrap();
        let _ = router
            .serve(
                &mut conn,
                peer_key,
                Some(Duration::from_millis(2600)),
                &mut no_out,
            )
            .await;
        let b_router = server.await.unwrap();
        // Both sides adopted a parent (one rooted, the other attached).
        assert!(router.parent().is_some());
        assert!(b_router.parent().is_some());
        // Both agree on the root.
        assert_eq!(
            router.root_and_depth().map(|(r, _)| r),
            b_router.root_and_depth().map(|(r, _)| r)
        );
    }

    #[tokio::test]
    async fn session_payload_loopback() {
        // Full stack over loopback: lookup + session + encrypted delivery.
        let a_sk = SigningKey::from_bytes(&[0x30; 32]);
        let b_sk = SigningKey::from_bytes(&[0x40; 32]);
        let b_pub = b_sk.verifying_key().to_bytes();
        let a_pub = a_sk.verifying_key().to_bytes();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _) = crate::link::run_handshake(&mut sock, &b_sk, &opts, true)
                .await
                .unwrap();
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                stream: sock,
            };
            let mut router = Router::new(b_sk);
            let mut no_out = Vec::new();
            router.register(&mut conn, key).await.unwrap();
            let _ = router
                .serve(&mut conn, key, Some(Duration::from_secs(10)), &mut no_out)
                .await;
            router
        });
        let uri = format!("tcp://{addr}");
        let mut conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        assert_eq!(peer_key, b_pub);
        let mut router = Router::new(a_sk);
        router.register(&mut conn, peer_key).await.unwrap();
        let mut outgoing = vec![(b_pub, b"ping-0".to_vec())];
        let _ = router
            .serve(
                &mut conn,
                peer_key,
                Some(Duration::from_secs(10)),
                &mut outgoing,
            )
            .await;
        let b_router = server.await.unwrap();
        assert!(
            b_router
                .inbox
                .iter()
                .any(|(from, msg)| *from == a_pub && msg == b"ping-0"),
            "B inbox: {:?}",
            b_router
                .inbox
                .iter()
                .map(|(f, m)| (hex::encode(f), m.clone()))
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn resolve_loopback() {
        // A resolves B's IPv6 address to B's full key over a live link.
        let a_sk = SigningKey::from_bytes(&[0x60; 32]);
        let b_sk = SigningKey::from_bytes(&[0x70; 32]);
        let b_pub = b_sk.verifying_key().to_bytes();
        let b_addr = crate::address::addr_for_key(&b_pub);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _) = crate::link::run_handshake(&mut sock, &b_sk, &opts, true)
                .await
                .unwrap();
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                stream: sock,
            };
            let mut router = Router::new(b_sk);
            let mut no_out = Vec::new();
            router.register(&mut conn, key).await.unwrap();
            let _ = router
                .serve(&mut conn, key, Some(Duration::from_secs(8)), &mut no_out)
                .await;
            router
        });
        let uri = format!("tcp://{addr}");
        let mut conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        let mut router = Router::new(a_sk);
        router.register(&mut conn, peer_key).await.unwrap();
        // Converge first (mirrors serve slices): maintain + dispatch.
        {
            let mut links = LinkSet::single(peer_key, &mut conn);
            let end = tokio::time::Instant::now() + Duration::from_secs(4);
            while tokio::time::Instant::now() < end {
                router.maintain(&mut links, peer_key).await.unwrap();
                if let Ok(Ok((ftype, payload))) = tokio::time::timeout(
                    Duration::from_millis(300),
                    links.get(&peer_key).unwrap().read_frame(),
                )
                .await
                {
                    router.frames[ftype as usize] += 1;
                    router
                        .dispatch_frame(&mut links, peer_key, ftype, &payload)
                        .await
                        .unwrap();
                }
                if router.parent().is_some() && router.root_path().is_some() {
                    break;
                }
            }
        }
        assert!(router.parent().is_some(), "A converged");
        let found = router
            .resolve(&mut conn, peer_key, &b_addr, Duration::from_secs(5))
            .await
            .expect("resolve B addr");
        assert_eq!(found, b_pub);
        let _ = server.await;
    }

    #[tokio::test]
    async fn resolve_subnet_loopback() {
        // A resolves an address inside B's routed /64 to B's full key.
        let a_sk = SigningKey::from_bytes(&[0x30; 32]);
        let b_sk = SigningKey::from_bytes(&[0x40; 32]);
        let b_pub = b_sk.verifying_key().to_bytes();
        let b_snet = crate::address::subnet_for_key(&b_pub);
        let mut target_raw = [0u8; 16];
        target_raw[..8].copy_from_slice(&b_snet.0);
        target_raw[15] = 0x41;
        let target = crate::address::Address(target_raw);
        assert!(target.0[0] == crate::address::NODE_PREFIX | crate::address::SUBNET_BIT);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut sock = sock;
            let opts = LinkOptions::default();
            let (key, _) = crate::link::run_handshake(&mut sock, &b_sk, &opts, true)
                .await
                .unwrap();
            let mut conn = crate::link::PeerConn::<Tcp> {
                remote_key: key,
                priority: 0,
                stream: sock,
            };
            let mut router = Router::new(b_sk);
            let mut no_out = Vec::new();
            router.register(&mut conn, key).await.unwrap();
            let _ = router
                .serve(&mut conn, key, Some(Duration::from_secs(8)), &mut no_out)
                .await;
            router
        });
        let uri = format!("tcp://{addr}");
        let mut conn = crate::link::dial(&uri, &a_sk, &LinkOptions::default())
            .await
            .unwrap();
        let peer_key = conn.remote_key;
        let mut router = Router::new(a_sk);
        router.register(&mut conn, peer_key).await.unwrap();
        {
            let mut links = LinkSet::single(peer_key, &mut conn);
            let end = tokio::time::Instant::now() + Duration::from_secs(4);
            while tokio::time::Instant::now() < end {
                router.maintain(&mut links, peer_key).await.unwrap();
                if let Ok(Ok((ftype, payload))) = tokio::time::timeout(
                    Duration::from_millis(300),
                    links.get(&peer_key).unwrap().read_frame(),
                )
                .await
                {
                    router.frames[ftype as usize] += 1;
                    router
                        .dispatch_frame(&mut links, peer_key, ftype, &payload)
                        .await
                        .unwrap();
                }
                if router.parent().is_some() && router.root_path().is_some() {
                    break;
                }
            }
        }
        assert!(router.parent().is_some(), "A converged");
        let found = router
            .resolve(&mut conn, peer_key, &target, Duration::from_secs(10))
            .await;
        let found = found.expect("resolve B subnet addr");
        assert_eq!(found, b_pub);
        let _ = server.await;
    }
}
