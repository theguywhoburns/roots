//! Read-only router views: snapshot queries for diagnostics and the admin adapter.
//! Pure borrows over the composed tables; the lib never prints (see `dump`).

use std::time::{Duration, Instant};

use crate::address::KEY_LEN;
use crate::router::Router;
use crate::traits::Snapshot;

impl Router {
    pub fn parent(&self) -> Option<[u8; KEY_LEN]> {
        self.tree.infos.get(&self.pubkey).map(|i| i.parent)
    }

    pub fn root_and_depth(&self) -> Option<([u8; KEY_LEN], usize)> {
        let mut next = self.pubkey;
        let mut depth = 0;
        loop {
            let info = self.tree.infos.get(&next)?;
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
        self.tree.infos.len()
    }

    /// Debug snapshot of tree + path + link state. Returns text instead of
    /// printing: the lib never writes to stderr; binaries decide (gated
    /// behind `ROOTS_DBG_DUMP` in `src/main.rs`).
    pub fn dump(&self) -> String {
        let mut out = String::new();
        let mut peers: Vec<_> = self.tree.links.values().collect();
        peers.sort_by_key(|l| (l.peer, l.order));
        for l in peers {
            // `kind` is roots-only diagnostics (our `dump` format, never on
            // the wire): `go` vs `roots`. Gated behavior fixes key off this.
            let kind = if l.kind.is_roots() { "roots" } else { "go" };
            out.push_str(&format!(
                "PEER key={} prio={} order={} impl={kind}\n",
                hex::encode(l.peer),
                l.prio,
                l.order
            ));
        }
        let mut keys: Vec<_> = self.tree.infos.keys().collect();
        keys.sort();
        for k in keys {
            let i = &self.tree.infos[k];
            out.push_str(&format!(
                "INFO key={} parent={} seq={} port={}\n",
                hex::encode(k),
                hex::encode(i.parent),
                i.res.req.seq,
                i.res.port
            ));
        }
        let mut paths: Vec<_> = self.path.entries.keys().collect();
        paths.sort();
        for k in paths {
            let e = &self.path.entries[k];
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
        self.path.entries.contains_key(key)
    }

    /// True when an E2E session exists for `key` (for diagnostics).
    pub fn has_session(&self, key: &[u8; KEY_LEN]) -> bool {
        self.sess.sessions.contains_key(key)
    }

    /// Learned source route + notify seq for `key` (for diagnostics).
    pub fn path_details(&self, key: &[u8; KEY_LEN]) -> Option<(Vec<u64>, u64)> {
        self.path.entries.get(key).map(|e| (e.path.clone(), e.seq))
    }

    /// All learned source routes as `(key, path, seq)`, sorted by key
    /// (for diagnostics / admin adapter).
    pub fn get_paths(&self) -> Vec<([u8; KEY_LEN], Vec<u64>, u64)> {
        let mut out: Vec<_> = self
            .path
            .entries
            .iter()
            .map(|(k, e)| (*k, e.path.clone(), e.seq))
            .collect();
        out.sort_by_key(|(k, _, _)| *k);
        out
    }

    /// Peer keys with an open E2E session, sorted (for diagnostics).
    pub fn get_sessions(&self) -> Vec<[u8; KEY_LEN]> {
        let mut out: Vec<_> = self.sess.sessions.keys().copied().collect();
        out.sort();
        out
    }

    /// Direct links, one row per **connection**, sorted by key then age: the
    /// router's half of a `getPeers` row — Go's `DebugPeerInfo`
    /// (`ironwood/network/debug.go:71-91`), which `Core.GetPeers` joins to the
    /// link's own counters by connection identity (`core/api.go:71-103`).
    ///
    /// Per link, not per key, because that is what Go iterates: a node we hold
    /// two connections to contributes two rows, each with its own priority, lag
    /// and round trip. `responded` tracks the last `SigReq` round trip on that
    /// link, and `lag_ms` is Go's EWMA in whole milliseconds — 4294967295 for a
    /// link that has not answered one yet, because that is Go's
    /// `routerUnknownLatency` in *nanoseconds* (`router.go:39`).
    pub fn link_peers(&self) -> Vec<LinkPeer> {
        let mut out: Vec<LinkPeer> = self
            .tree
            .links
            .iter()
            .map(|(id, l)| LinkPeer {
                id: *id,
                key: l.peer,
                port: self.tree.peers.get(&l.peer).map(|p| p.port).unwrap_or(0),
                priority: l.prio,
                responded: l.responded,
                lag_ms: l.lag.as_millis(),
                latency: go_latency(l.srrt, l.sent_at),
            })
            .collect();
        out.sort_by_key(|p| (p.key, p.id));
        out
    }

    /// Soft sends discarded because the chosen next hop has no open link.
    /// Go has no equivalent counter (it drops them in silence); this is the
    /// only trace those drops leave.
    pub fn dropped_no_link(&self) -> u64 {
        self.dropped_no_link
    }

    /// The link a payload for `dest` would leave by: the greedy next hop toward
    /// `dest`'s position in the spanning tree.
    ///
    /// This is Go's `_lookup` (`router.go:685-757`) asked as a question rather
    /// than as a send, for a caller that wants to know *where* a packet to
    /// `dest` would leave without sending one.
    ///
    /// Nothing in this repo calls it, and that is worth saying because the
    /// obvious candidate — the remote admin queries — turned out not to need it.
    /// They hand the request to `request_nodeinfo`/`request_debug`, which reach
    /// `pathfinder_send` and so get their next hop from the send path itself; Go
    /// reaches the same place through `PacketConn.WriteTo` (`core/proto.go:101`,
    /// `core/nodeinfo.go:114`). Asking for a next hop separately and then writing
    /// to it would be a second, possibly different, answer to one question.
    ///
    /// `None` means no live link takes us closer, which is what `_lookup` says
    /// and is not an error: it is how a node with no route answers.
    pub fn next_hop(
        &self,
        links: &crate::link::LinkSet,
        dest: &[u8; KEY_LEN],
    ) -> Option<crate::link::LinkId> {
        let path = self.root_path_for(dest)?;
        // A fresh watermark, as Go's `WriteTo` gets: `traffic.watermark =
        // ^uint64(0)` (packetconn.go:86), so the first candidate always wins on
        // distance and the cost comparison only breaks ties.
        self.greedy_next(links, &path, &mut { u64::MAX })
    }

    /// Destinations we are holding a payload for, waiting on a DHT notify.
    ///
    /// Go keeps the same queue inside `pathfinder.rumors[xkey(dest)].traffic`
    /// and never exposes it, but a caller that queues a packet needs to be able
    /// to say how much is still in flight — otherwise a lookup that never
    /// completes is a black hole.
    pub fn pending_routes(&self) -> Vec<crate::address::Address> {
        let mut out: Vec<crate::address::Address> = self
            .path
            .rumors
            .values()
            .filter(|r| r.pending.is_some())
            .map(|r| {
                let want = r.dest;
                self.path
                    .entries
                    .keys()
                    .find(|k| crate::bloom::xkey(k) == crate::bloom::xkey(&want))
                    .map(crate::address::addr_for_key)
                    .unwrap_or_else(|| crate::address::addr_for_key(&want))
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Spanning-tree entries as `(key, parent, seq)`, sorted by key
    /// (for diagnostics / admin adapter).
    pub fn tree_entries(&self) -> Vec<([u8; KEY_LEN], [u8; KEY_LEN], u64)> {
        let mut out: Vec<_> = self
            .tree
            .infos
            .iter()
            .map(|(k, i)| (*k, i.parent, i.res.req.seq))
            .collect();
        out.sort_by_key(|(k, _, _)| *k);
        out
    }
}

/// What the router knows about one link: Go's `DebugPeerInfo`
/// (`ironwood/network/debug.go:24-35`), the half of a `getPeers` row that comes
/// from the tree rather than from the socket.
#[derive(Clone, Copy, Debug)]
pub struct LinkPeer {
    /// Which connection this row describes. Two links to one node are two rows,
    /// and the id is what tells them apart.
    pub id: crate::link::LinkId,
    pub key: [u8; KEY_LEN],
    /// The node's port, which every link to that key shares.
    pub port: u64,
    pub priority: u8,
    /// True once the peer has answered one of our `SigReq`s.
    pub responded: bool,
    /// Go's `_getCost` input: the lag EWMA in whole milliseconds
    /// (`ironwood/network/router.go:221-227`).
    pub lag_ms: u128,
    /// Go's `latency`: the last `SigReq` round trip, re-read at query time
    /// (`debug.go:84-86`).
    pub latency: Option<Duration>,
}

/// Go's `peer.srrt.Sub(peer.srst).Round(time.Millisecond / 100)`, kept only if
/// the result is positive (`debug.go:84`). Two behaviours hide in that one line:
/// the pair is *stored* timestamps, so the number grows until the next `SigReq`
/// resets it, and a `SigReq` sent after the last `SigRes` makes it negative,
/// which reports as no latency at all rather than a small one.
fn go_latency(srrt: Option<Instant>, srst: Option<Instant>) -> Option<Duration> {
    let delta = srrt?.checked_duration_since(srst?)?;
    let hundredths = (delta.as_nanos() as u64 + 5_000) / 10_000;
    (hundredths > 0).then(|| Duration::from_nanos(hundredths * 10_000))
}

impl Snapshot for Router {
    fn parent(&self) -> Option<[u8; KEY_LEN]> {
        self.parent()
    }
    fn root_and_depth(&self) -> Option<([u8; KEY_LEN], usize)> {
        self.root_and_depth()
    }
    fn known_nodes(&self) -> usize {
        self.known_nodes()
    }
    fn has_path(&self, key: &[u8; KEY_LEN]) -> bool {
        self.has_path(key)
    }
    fn has_session(&self, key: &[u8; KEY_LEN]) -> bool {
        self.has_session(key)
    }
    fn path_details(&self, key: &[u8; KEY_LEN]) -> Option<(Vec<u64>, u64)> {
        self.path_details(key)
    }
    fn get_paths(&self) -> Vec<([u8; KEY_LEN], Vec<u64>, u64)> {
        self.get_paths()
    }
    fn get_sessions(&self) -> Vec<[u8; KEY_LEN]> {
        self.get_sessions()
    }
    fn link_peers(&self) -> Vec<LinkPeer> {
        self.link_peers()
    }
    fn tree_entries(&self) -> Vec<([u8; KEY_LEN], [u8; KEY_LEN], u64)> {
        self.tree_entries()
    }
    fn dump(&self) -> String {
        self.dump()
    }
}
