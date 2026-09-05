//! Spanning-tree router core. Ports of `ironwood/network/router.go` wire
//! types plus the deterministic parent-selection / announce rules.
//!
//! Wire encodings (all integers are LEB128 uvarints):
//! - `SigReq`: `seq + nonce`
//! - `SigRes`: `SigReq + port + psig[64]`, where
//!   `psig = Sign(parent, node || parent || seq || nonce || port)`
//! - `Announce`: `key[32] + parent[32] + SigRes + sig[64]`, where
//!   `sig = Sign(key, key || parent || seq || nonce || port)`

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::address::KEY_LEN;
use crate::bloom::BloomFilter;
use crate::error::Error;
use crate::frame::{FrameType, append_uvarint, read_uvarint};
use crate::link::{Link, LinkSet};
use crate::pathfind::NotifyInfo;
use crate::session::Session;

/// Router maintenance tick (Go: 1s).
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);
/// Self-announce refresh (Go: `routerRefresh` 4min).
pub const ROUTER_REFRESH: Duration = Duration::from_secs(4 * 60);
/// Expiry for other nodes' infos (Go: `routerTimeout` 5min).
pub const ROUTER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Unknown-link latency sentinel (Go: `routerUnknownLatency`).
pub const UNKNOWN_LATENCY: Duration = Duration::from_millis(u32::MAX as u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigReq {
    pub seq: u64,
    pub nonce: u64,
}

impl SigReq {
    pub fn encode(&self, out: &mut Vec<u8>) {
        append_uvarint(out, self.seq);
        append_uvarint(out, self.nonce);
    }

    /// Decode, returning bytes consumed. Caller must enforce exact length.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Error> {
        let (seq, n) = read_uvarint(buf).ok_or(Error::InvalidLength)?;
        let (nonce, m) = read_uvarint(&buf[n..]).ok_or(Error::InvalidLength)?;
        Ok((Self { seq, nonce }, n + m))
    }

    pub fn bytes_for_sig(&self, node: &[u8; KEY_LEN], parent: &[u8; KEY_LEN]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 * KEY_LEN + 20);
        out.extend_from_slice(node);
        out.extend_from_slice(parent);
        self.encode(&mut out);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigRes {
    pub req: SigReq,
    pub port: u64,
    pub psig: [u8; 64],
}

impl SigRes {
    pub fn bytes_for_sig(&self, node: &[u8; KEY_LEN], parent: &[u8; KEY_LEN]) -> Vec<u8> {
        let mut out = self.req.bytes_for_sig(node, parent);
        append_uvarint(&mut out, self.port);
        out
    }

    /// Build a signed response. The signature covers node + parent + req +
    /// port (Go `routerSigRes.bytesForSig`), not the bare request.
    pub fn seal(
        req: SigReq,
        port: u64,
        node: &[u8; KEY_LEN],
        parent: &SigningKey,
        parent_key: &[u8; KEY_LEN],
    ) -> Self {
        let mut res = Self {
            req,
            port,
            psig: [0u8; 64],
        };
        res.psig = parent.sign(&res.bytes_for_sig(node, parent_key)).to_bytes();
        res
    }

    pub fn check(&self, node: &[u8; KEY_LEN], parent: &[u8; KEY_LEN]) -> bool {
        let bs = self.bytes_for_sig(node, parent);
        VerifyingKey::from_bytes(parent)
            .and_then(|k| k.verify_strict(&bs, &ed25519_dalek::Signature::from_bytes(&self.psig)))
            .is_ok()
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        self.req.encode(out);
        append_uvarint(out, self.port);
        out.extend_from_slice(&self.psig);
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Error> {
        let (req, n) = SigReq::decode(buf)?;
        let rest = &buf[n..];
        let (port, m) = read_uvarint(rest).ok_or(Error::InvalidLength)?;
        let rest = &rest[m..];
        if rest.len() < 64 {
            return Err(Error::InvalidLength);
        }
        let mut psig = [0u8; 64];
        psig.copy_from_slice(&rest[..64]);
        Ok((Self { req, port, psig }, n + m + 64))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announce {
    pub key: [u8; KEY_LEN],
    pub parent: [u8; KEY_LEN],
    pub res: SigRes,
    pub sig: [u8; 64],
}

impl Announce {
    pub fn check(&self) -> bool {
        if self.res.port == 0 && self.key != self.parent {
            return false;
        }
        let bs = self.res.bytes_for_sig(&self.key, &self.parent);
        let sig_ok = VerifyingKey::from_bytes(&self.key)
            .and_then(|k| k.verify_strict(&bs, &ed25519_dalek::Signature::from_bytes(&self.sig)))
            .is_ok();
        sig_ok && self.res.check(&self.key, &self.parent)
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.parent);
        self.res.encode(out);
        out.extend_from_slice(&self.sig);
    }

    pub fn decode_exact(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 2 * KEY_LEN {
            return Err(Error::InvalidLength);
        }
        let mut key = [0u8; KEY_LEN];
        let mut parent = [0u8; KEY_LEN];
        key.copy_from_slice(&buf[..KEY_LEN]);
        parent.copy_from_slice(&buf[KEY_LEN..2 * KEY_LEN]);
        let (res, n) = SigRes::decode(&buf[2 * KEY_LEN..])?;
        let rest = &buf[2 * KEY_LEN + n..];
        if rest.len() != 64 {
            return Err(Error::InvalidLength);
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(rest);
        Ok(Self {
            key,
            parent,
            res,
            sig,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Info {
    pub(crate) parent: [u8; KEY_LEN],
    pub(crate) res: SigRes,
    pub(crate) sig: [u8; 64],
}

impl Info {
    fn announce(&self, key: [u8; KEY_LEN]) -> Announce {
        Announce {
            key,
            parent: self.parent,
            res: self.res,
            sig: self.sig,
        }
    }
}

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

/// Single-peer spanning-tree router. Multi-peer maps are keyed by node key so
/// growing to a full mesh node needs no restructuring. Peer I/O stays in
/// `serve` (one `PeerConn`); all protocol state lives here so additional
/// links only need a connection map later.
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

    fn new_req(&self) -> SigReq {
        SigReq {
            seq: self
                .infos
                .get(&self.pubkey)
                .map(|i| i.res.req.seq + 1)
                .unwrap_or(1),
            nonce: rand::random(),
        }
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

    async fn send_req(
        &mut self,
        links: &mut LinkSet<'_>,
        peer_key: [u8; KEY_LEN],
    ) -> Result<(), Error> {
        let req = self.new_req();
        if let Some(p) = self.peers.get_mut(&peer_key) {
            p.req = req;
            p.responded = false;
            p.sent_at = Some(Instant::now());
        }
        let mut out = Vec::new();
        req.encode(&mut out);
        links.write(peer_key, FrameType::SigReq, &out).await
    }

    /// Answer an inbound SigReq (Go `_handleRequest`).
    async fn handle_request(
        &mut self,
        links: &mut LinkSet<'_>,
        peer_key: [u8; KEY_LEN],
        req: SigReq,
    ) -> Result<(), Error> {
        let port = self.peers.get(&peer_key).map(|p| p.port).unwrap_or(0);
        let res = SigRes::seal(req, port, &peer_key, &self.key, &self.pubkey);
        let mut out = Vec::new();
        res.encode(&mut out);
        links.write(peer_key, FrameType::SigRes, &out).await
    }

    /// Handle an inbound SigRes, checking it answers our open request and
    /// updating the RTT estimate (Go `_handleResponse` + peer `srst/srrt`).
    fn handle_response(&mut self, peer_key: [u8; KEY_LEN], res: SigRes) {
        let rtt = self
            .peers
            .get(&peer_key)
            .and_then(|p| p.sent_at)
            .map(|t| t.elapsed());
        let matches = self
            .peers
            .get(&peer_key)
            .map(|p| p.req == res.req)
            .unwrap_or(false);
        if !matches || !res.check(&self.pubkey, &peer_key) {
            return;
        }
        self.responses.entry(peer_key).or_insert(res);
        if let (Some(p), Some(rtt)) = (self.peers.get_mut(&peer_key), rtt)
            && !p.responded
        {
            p.responded = true;
            p.lag = if p.lag == UNKNOWN_LATENCY {
                rtt * 2
            } else {
                p.lag * 7 / 8 + rtt.min(p.lag * 2) / 8
            };
        }
    }

    /// Insert announce info under Go's exact precedence rules (Go `_update`):
    /// higher seq wins, then lower parent, then lower nonce. Returns true if
    /// the info was adopted.
    fn update(&mut self, ann: &Announce) -> bool {
        if let Some(info) = self.infos.get(&ann.key) {
            let fresh = (
                ann.res.req.seq,
                std::cmp::Reverse(ann.parent),
                std::cmp::Reverse(ann.res.req.nonce),
            );
            let known = (
                info.res.req.seq,
                std::cmp::Reverse(info.parent),
                std::cmp::Reverse(info.res.req.nonce),
            );
            if fresh <= known {
                return false;
            }
        }
        for sent in self.sent.values_mut() {
            sent.remove(&ann.key);
        }
        let deadline = if ann.key == self.pubkey {
            ROUTER_REFRESH
        } else {
            ROUTER_TIMEOUT
        };
        self.info_deadlines
            .insert(ann.key, Instant::now() + deadline);
        self.infos.insert(
            ann.key,
            Info {
                parent: ann.parent,
                res: ann.res,
                sig: ann.sig,
            },
        );
        true
    }

    fn expire(&mut self) {
        let now = Instant::now();
        let dead: Vec<[u8; KEY_LEN]> = self
            .info_deadlines
            .iter()
            .filter(|(_, d)| **d <= now)
            .map(|(k, _)| *k)
            .collect();
        for k in dead {
            self.info_deadlines.remove(&k);
            self.infos.remove(&k);
            for sent in self.sent.values_mut() {
                sent.remove(&k);
            }
        }
        if self.self_refresh_at.map(|t| t <= now).unwrap_or(false) {
            self.refresh = true;
            self.self_refresh_at = Some(now + ROUTER_REFRESH);
        }
    }

    fn cost(&self, peer_key: &[u8; KEY_LEN]) -> u64 {
        let ms = self
            .peers
            .get(peer_key)
            .map(|p| p.lag.as_millis() as u64)
            .unwrap_or(0);
        ms.max(1)
    }

    fn root_and_dists(&self, dest: &[u8; KEY_LEN]) -> ([u8; KEY_LEN], HashMap<[u8; KEY_LEN], u64>) {
        let mut dists = HashMap::new();
        let mut next = *dest;
        let mut root = *dest;
        let mut dist = 0;
        loop {
            if dists.contains_key(&next) {
                break;
            }
            if let Some(info) = self.infos.get(&next) {
                root = next;
                dists.insert(next, dist);
                dist += 1;
                next = info.parent;
            } else {
                break;
            }
        }
        (root, dists)
    }

    /// Deterministic parent selection (Go `_fix`). Returns announces to send.
    async fn fix(&mut self, links: &mut LinkSet<'_>, peer_key: [u8; KEY_LEN]) -> Result<(), Error> {
        let self_info = self.infos.get(&self.pubkey).copied();
        let mut best_root = self.pubkey;
        let mut best_parent = self.pubkey;
        let mut best_cost = u64::MAX;
        if let Some(info) = self_info
            && self.peers.contains_key(&info.parent)
        {
            let (root, dists) = self.root_and_dists(&self.pubkey);
            if root < best_root
                && let Some(d) = dists.get(&root)
            {
                best_root = root;
                best_parent = info.parent;
                best_cost = d.saturating_mul(self.cost(&info.parent));
            }
        }
        let mut candidates: Vec<([u8; KEY_LEN], SigRes)> =
            self.responses.iter().map(|(k, r)| (*k, *r)).collect();
        candidates.sort_by_key(|(k, _)| *k);
        for (pk, _res) in &candidates {
            let Some(_) = self.infos.get(pk) else {
                continue;
            };
            let (p_root, p_dists) = self.root_and_dists(pk);
            if p_dists.contains_key(&self.pubkey) {
                continue;
            }
            let cost = p_dists
                .get(&p_root)
                .copied()
                .unwrap_or(u64::MAX)
                .saturating_mul(self.cost(pk));
            if p_root < best_root {
                best_root = p_root;
                best_parent = *pk;
                best_cost = cost;
            } else if p_root != best_root {
                continue;
            }
            let cur_parent = self_info.map(|i| i.parent);
            if (self.refresh && cost.saturating_mul(2) < best_cost)
                || (Some(best_parent) != cur_parent && cost < best_cost)
            {
                best_root = p_root;
                best_parent = *pk;
                best_cost = cost;
            }
        }
        let cur_parent = self_info.map(|i| i.parent);
        if self.refresh || self.do_root1 || self.do_root2 || cur_parent != Some(best_parent) {
            if best_root != self.pubkey
                && let Some(res) = self.responses.get(&best_parent).copied()
                && self.use_response(best_parent, &res)
            {
                self.refresh = false;
                self.do_root1 = false;
                self.do_root2 = false;
                self.send_all_reqs(links).await?;
            } else if self.do_root2 {
                self.become_root();
                self.refresh = false;
                self.do_root1 = false;
                self.do_root2 = false;
                self.send_all_reqs(links).await?;
            } else if !self.do_root1 {
                self.do_root1 = true;
            }
        }
        let _ = peer_key;
        Ok(())
    }

    fn use_response(&mut self, peer_key: [u8; KEY_LEN], res: &SigRes) -> bool {
        let bs = res.bytes_for_sig(&self.pubkey, &peer_key);
        let info = Info {
            parent: peer_key,
            res: *res,
            sig: self.key.sign(&bs).to_bytes(),
        };
        let ann = info.announce(self.pubkey);
        if ann.check() {
            self.update(&ann)
        } else {
            false
        }
    }

    fn become_root(&mut self) {
        let req = self.new_req();
        let pubkey = self.pubkey;
        let res = SigRes::seal(req, 0, &pubkey, &self.key, &pubkey);
        let ann = Announce {
            key: self.pubkey,
            parent: self.pubkey,
            res,
            sig: res.psig,
        };
        debug_assert!(ann.check());
        self.update(&ann);
        self.self_refresh_at = Some(Instant::now() + ROUTER_REFRESH);
    }

    async fn send_all_reqs(&mut self, links: &mut LinkSet<'_>) -> Result<(), Error> {
        // Go `_sendReqs` clears req/res state and re-requests every peer.
        self.responses.clear();
        let keys: Vec<[u8; KEY_LEN]> = self.peers.keys().copied().collect();
        for k in keys {
            self.send_req(links, k).await?;
        }
        Ok(())
    }

    fn ancestry(&self, key: &[u8; KEY_LEN]) -> Vec<[u8; KEY_LEN]> {
        let mut anc = vec![*key];
        let mut here = *key;
        loop {
            if let Some(info) = self.infos.get(&here) {
                if anc.contains(&info.parent) {
                    break;
                }
                anc.push(info.parent);
                here = info.parent;
            } else {
                anc.pop();
                break;
            }
        }
        anc.reverse();
        anc
    }

    /// Send unsent ancestry announces to one peer (Go `_sendAnnounces`).
    async fn send_announces(
        &mut self,
        links: &mut LinkSet<'_>,
        peer_key: [u8; KEY_LEN],
    ) -> Result<(), Error> {
        let mut to_send: Vec<[u8; KEY_LEN]> = Vec::new();
        let self_anc = self.ancestry(&self.pubkey);
        let peer_anc = self.ancestry(&peer_key);
        {
            let sent = self.sent.entry(peer_key).or_default();
            for k in self_anc.into_iter().chain(peer_anc) {
                if !sent.contains(&k) {
                    sent.insert(k);
                    to_send.push(k);
                }
            }
        }
        for k in to_send {
            if let Some(info) = self.infos.get(&k) {
                let ann = info.announce(k);
                let mut buf = Vec::new();
                ann.encode(&mut buf);
                links.write(peer_key, FrameType::Announce, &buf).await?;
                self.announces_sent += 1;
            }
        }
        Ok(())
    }

    fn handle_announce(
        &mut self,
        _links: &mut LinkSet<'_>,
        from: [u8; KEY_LEN],
        ann: &Announce,
    ) -> Option<Announce> {
        // Returns a "here is better" reply announce when warranted, so the
        // caller can send it back to the original sender only.
        self.announces_recv += 1;
        let adopted = self.update(ann);
        if adopted {
            if ann.key == self.pubkey {
                self.refresh = true;
            }
            self.sent.entry(from).or_default().insert(ann.key);
            None
        } else {
            self.sent.entry(from).or_default().insert(ann.key);
            self.infos
                .get(&ann.key)
                .filter(|info| {
                    **info
                        != (Info {
                            parent: ann.parent,
                            res: ann.res,
                            sig: ann.sig,
                        })
                })
                .map(|info| info.announce(ann.key))
        }
    }

    /// Resolve an IPv6 address to its full node key: look up the partial
    /// key until a signed path-notify names a key with this address.
    /// Handles both node addresses (`02…`) and routed subnets (`03…`, resolved
    /// to the owning node). Returns the key (also usable directly for
    /// [`Router::session_send`] via the `serve` outbox). Times out with
    /// [`Error::Timeout`].
    pub async fn resolve(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        addr: &crate::address::Address,
        timeout: Duration,
    ) -> Result<[u8; KEY_LEN], Error> {
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
            match tokio::time::timeout(wait, conn.read_frame()).await {
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
        self.bloom_maintenance(links, peer_key).await?;
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
        links: &mut LinkSet<'_>,
        peer_key: [u8; KEY_LEN],
        hold_for: Option<Duration>,
        outgoing: &mut Vec<([u8; KEY_LEN], Vec<u8>)>,
    ) -> Result<(), Error> {
        // Previously failed payloads go first (at-least-once across links).
        outgoing.splice(..0, std::mem::take(&mut self.resend));
        let end = hold_for.map(|h| tokio::time::Instant::now() + h);
        let mut last_maintain = tokio::time::Instant::now();
        self.maintain(links, peer_key).await?;
        loop {
            let now = tokio::time::Instant::now();
            if let Some(end) = end
                && now >= end
            {
                break;
            }
            for (dest, msg) in std::mem::take(outgoing) {
                self.session_send(links, peer_key, dest, msg).await?;
            }
            if now.duration_since(last_maintain) >= MAINTENANCE_INTERVAL {
                last_maintain = now;
                self.maintain(links, peer_key).await?;
            }
            let timeout = end
                .map(|e| e.saturating_duration_since(now))
                .unwrap_or(MAINTENANCE_INTERVAL)
                .min(MAINTENANCE_INTERVAL);
            match tokio::time::timeout(timeout, conn.read_frame()).await {
                Ok(Ok((ftype, payload))) => {
                    self.frames[ftype as usize] += 1;
                    self.dispatch_frame(links, peer_key, ftype, &payload).await?;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {}
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

    fn keys(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    #[test]
    fn sigreq_roundtrip_exact() {
        let req = SigReq {
            seq: 300,
            nonce: 99,
        };
        let mut buf = Vec::new();
        req.encode(&mut buf);
        let (dec, n) = SigReq::decode(&buf).unwrap();
        assert_eq!((dec, n), (req, buf.len()));
        // Trailing garbage must be rejected by callers (exact-length rule).
        buf.push(0);
        let (dec2, n2) = SigReq::decode(&buf).unwrap();
        assert_eq!(dec2, req);
        assert_eq!(n2, buf.len() - 1);
    }

    fn make_tree() -> (SigningKey, SigningKey, SigningKey, Announce, Announce) {
        // root R <- parent P <- leaf L, each announce correctly chained.
        let r = keys(1);
        let p = keys(2);
        let l = keys(3);
        let rp = r.verifying_key().to_bytes();
        let pp = p.verifying_key().to_bytes();
        // R self-roots with port 0.
        let rreq = SigReq { seq: 1, nonce: 7 };
        let rres = SigRes::seal(rreq, 0, &rp, &r, &rp);
        let rann = Announce {
            key: rp,
            parent: rp,
            res: rres,
            sig: rres.psig,
        };
        assert!(rann.check());
        // P attaches under R with R's port 5 for the link.
        let preq = SigReq { seq: 1, nonce: 8 };
        let pres = SigRes::seal(preq, 5, &pp, &r, &rp);
        let pann = Announce {
            key: pp,
            parent: rp,
            res: pres,
            sig: p.sign(&pres.bytes_for_sig(&pp, &rp)).to_bytes(),
        };
        assert!(pann.check());
        let _ = l;
        (r, p, l, rann, pann)
    }

    #[test]
    fn announce_chain_verifies() {
        let (_r, _p, _l, rann, pann) = make_tree();
        for ann in [rann, pann] {
            let mut buf = Vec::new();
            ann.encode(&mut buf);
            let dec = Announce::decode_exact(&buf).unwrap();
            assert_eq!(dec, ann);
            assert!(dec.check());
        }
    }

    #[test]
    fn announce_rejects_tampering() {
        let (_r, _p, _l, rann, _pann) = make_tree();
        let mut buf = Vec::new();
        rann.encode(&mut buf);
        // Flip a bit in the parent key: signatures must fail.
        buf[KEY_LEN] ^= 0x01;
        let dec = Announce::decode_exact(&buf).unwrap();
        assert!(!dec.check());
        // Non-root with port 0 is invalid even if signed.
        let bad = Announce {
            key: [9; KEY_LEN],
            parent: [8; KEY_LEN],
            res: SigRes {
                req: SigReq { seq: 1, nonce: 1 },
                port: 0,
                psig: [0; 64],
            },
            sig: [0; 64],
        };
        assert!(!bad.check());
    }

    #[test]
    fn update_precedence_matches_go() {
        let sk = keys(4);
        let mut router = Router::new(sk);
        let (_r, _p, _l, rann, pann) = make_tree();
        assert!(router.update(&rann));
        assert!(router.update(&pann));
        // Older seq loses.
        let mut older = pann;
        older.res.req.seq -= 1;
        assert!(!router.update(&older));
        // Same seq, worse (higher) parent loses.
        let mut worse = pann;
        worse.parent = [0xff; KEY_LEN];
        assert!(!router.update(&worse));
        // Identical re-announce loses (no churn).
        assert!(!router.update(&pann));
    }

    #[test]
    fn ancestry_orders_root_first() {
        let sk = keys(4);
        let mut router = Router::new(sk);
        let (_r, p, _l, rann, pann) = make_tree();
        router.update(&rann);
        router.update(&pann);
        let pp = p.verifying_key().to_bytes();
        let rp = rann.key;
        assert_eq!(router.ancestry(&pp), vec![rp, pp]);
    }

    #[tokio::test]
    async fn mixed_transport_links_share_one_router() {
        // Slice 10a: one Router drives a TCP link and a WS link (the WS
        // side type-erased through `AnyConn`) as `&mut dyn Link`. Tree
        // converges and a session opens over the TCP leg.
        use crate::link::{AnyConn, Link};

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

        // Drive both links: maintain each, drain frames from each.
        let end = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < end {
            router.maintain(&mut tcp_conn, tcp_peer).await.unwrap();
            router.maintain(&mut ws_conn, ws_peer).await.unwrap();
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(100), tcp_conn.read_frame()).await
            {
                router.frames[ftype as usize] += 1;
                router
                    .dispatch_frame(&mut tcp_conn, tcp_peer, ftype, &payload)
                    .await
                    .unwrap();
            }
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(100), ws_conn.read_frame()).await
            {
                router.frames[ftype as usize] += 1;
                router
                    .dispatch_frame(&mut ws_conn, ws_peer, ftype, &payload)
                    .await
                    .unwrap();
            }
            if router.parent().is_some()
                && router.root_path().is_some()
                && router.known_nodes() >= 3
            {
                break;
            }
        }
        assert!(router.parent().is_some(), "converged over mixed links");
        assert!(router.known_nodes() >= 3, "learned both peers");

        // Full stack over the TCP leg through the same dyn interface.
        router
            .session_send(&mut tcp_conn, tcp_peer, s1_pub, vec![0])
            .await
            .unwrap();
        let end = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < end {
            if router.has_session(&s1_pub) {
                break;
            }
            router.maintain(&mut tcp_conn, tcp_peer).await.unwrap();
            router.maintain(&mut ws_conn, ws_peer).await.unwrap();
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(100), tcp_conn.read_frame()).await
            {
                router
                    .dispatch_frame(&mut tcp_conn, tcp_peer, ftype, &payload)
                    .await
                    .unwrap();
            }
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(100), ws_conn.read_frame()).await
            {
                router
                    .dispatch_frame(&mut ws_conn, ws_peer, ftype, &payload)
                    .await
                    .unwrap();
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
        let end = tokio::time::Instant::now() + Duration::from_secs(4);
        while tokio::time::Instant::now() < end {
            router.maintain(&mut conn, peer_key).await.unwrap();
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(300), conn.read_frame()).await
            {
                router.frames[ftype as usize] += 1;
                router
                    .dispatch_frame(&mut conn, peer_key, ftype, &payload)
                    .await
                    .unwrap();
            }
            if router.parent().is_some() && router.root_path().is_some() {
                break;
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
        let end = tokio::time::Instant::now() + Duration::from_secs(4);
        while tokio::time::Instant::now() < end {
            router.maintain(&mut conn, peer_key).await.unwrap();
            if let Ok(Ok((ftype, payload))) =
                tokio::time::timeout(Duration::from_millis(300), conn.read_frame()).await
            {
                router.frames[ftype as usize] += 1;
                router
                    .dispatch_frame(&mut conn, peer_key, ftype, &payload)
                    .await
                    .unwrap();
            }
            if router.parent().is_some() && router.root_path().is_some() {
                break;
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
