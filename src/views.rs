//! Read-only router views: snapshot queries for diagnostics and the admin adapter.
//! Pure borrows over the composed tables; the lib never prints (see `dump`).

use std::time::Duration;

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
/// the result is positive (`debug.go:84-85`). Three behaviours hide in that one
/// line:
///
/// * the pair is *stored* timestamps, so the number grows until the next `SigReq`
///   resets it;
/// * a `SigReq` sent after the last `SigRes` makes `srrt - srst` **negative**, and
///   Go's `> 0` gate drops it — so an inverted pair reports as *no* latency, not a
///   small one;
/// * `Round` quantises to 10 µs, so a 4 µs round trip is reported as *no* latency
///   too. That is why the unit is nanoseconds upstream and why the
///   `sub_millisecond_durations_survive_the_conversion_exactly` test exists.
fn go_latency(
    srrt: Option<roots_core::clock::Instant>,
    srst: Option<roots_core::clock::Instant>,
) -> Option<Duration> {
    let srrt = srrt?;
    let srst = srst?;
    let delta = srrt.duration_since(srst);
    // **The inverted case is handled by the `> 0` gate, not by an explicit
    // comparison — and that is worth stating because the obvious version of this
    // function was wrong about it.**
    //
    // `roots_core::clock::Instant::duration_since` **saturates**, so an inverted
    // pair arrives here as a zero rather than as a negative. That looks like it
    // needs an `if srrt < srst { return None }` in front. It does not: Go's
    // subtraction yields a negative and its `> 0` gate drops it, so Go's observable
    // is *absent*; and a clamped zero also quantises to zero and also fails `> 0`,
    // so ours is *absent* too. Same answer, reached differently.
    //
    // An earlier version of this comment claimed the clamp would report
    // `latency: 0` — which `omitempty` would drop, "a different observable from
    // Go's". That was false, and a mutation deleting the explicit check passed
    // all 238 tests, which is what exposed it. So there is no explicit check, and
    // the two lines that do the work are both load-bearing.
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

#[cfg(test)]
mod tests {
    use super::*;
    use roots_core::clock::Instant;

    /// An instant `ns` nanoseconds after the epoch, so a test can write a delta as
    /// a number instead of as an arithmetic chain.
    fn at(ns: u64) -> Instant {
        Instant::from_nanos(ns)
    }

    /// Go's `debug.go:85` line, one clause at a time.
    ///
    /// This function had **no test at all** until the clock was migrated onto
    /// `roots_core::clock`, at which point a mutation that deleted its inversion
    /// check passed the whole suite — which is only possible if nothing observes
    /// the function directly. So the clauses are pinned here.
    ///
    /// Go is `peer.srrt.Sub(peer.srst).Round(time.Millisecond / 100)` guarded by
    /// `if rtt > 0`.
    #[test]
    fn latency_follows_go_rounding_and_positivity() {
        // **Both timestamps are required.** Go reads two struct fields with no
        // presence flag, and `omitempty` on the result means a peer that has not
        // been asked yet simply has no field.
        //
        // The `srrt` here is deliberately **not** `at(0)`: the first version of this
        // test used the epoch, which is exactly what a `srst.unwrap_or(EPOCH)` mutant
        // substitutes, so the assertion passed with the presence check removed. A
        // missing `srst` against a *non-zero* `srrt` is what actually distinguishes
        // them, and it is the case that occurs — a peer replies, then its state is
        // rebuilt before the send is stamped.
        assert_eq!(go_latency(None, None), None);
        assert_eq!(
            go_latency(Some(at(20_000_000)), None),
            None,
            "a reply with no matching send is not a round trip"
        );
        assert_eq!(
            go_latency(None, Some(at(20_000_000))),
            None,
            "a send with no matching reply is not a round trip"
        );

        // A zero gap is not a latency. Go's `rtt > 0` rejects it.
        assert_eq!(go_latency(Some(at(0)), Some(at(0))), None);

        // **The inverted pair.** A `SigReq` sent *after* the last `SigRes` leaves
        // `srst > srrt`, and this is a real state, not a hypothetical — `send_sigreq`
        // stamps `sent_at` without waiting for the reply.
        //
        // Go subtracts to a negative and its `> 0` gate drops it. Ours saturates to
        // zero and the same gate drops it. Either way the field is **absent**, which
        // is the observable: a reported `latency: 0` would be a different answer.
        assert_eq!(
            go_latency(Some(at(1_000)), Some(at(2_000))),
            None,
            "an inverted pair reports no latency, not a small one"
        );

        // **The sub-quantum case.** 10 µs is `Round`'s granularity, so anything
        // under 5 µs rounds away to nothing and is reported as absent. Go's `Round`
        // rounds half *away from zero*, which is what the `+ 5_000` below mirrors.
        assert_eq!(go_latency(Some(at(4_999)), Some(at(0))), None);
        assert_eq!(
            go_latency(Some(at(5_000)), Some(at(0))),
            Some(Duration::from_nanos(10_000)),
            "exactly half a quantum rounds up, as Go's Round does"
        );

        // **The number that motivated the nanosecond representation**, from
        // `docs/protocol/21-admin.md`: Go reported `latency: 450000` — 450 µs — on
        // the link this repository measures. If the delta were held in
        // milliseconds this would quantise to nothing and the comparison against
        // `yggdrasilctl` would be meaningless.
        assert_eq!(
            go_latency(Some(at(450_000)), Some(at(0))),
            Some(Duration::from_nanos(450_000)),
            "450us must survive as 450us"
        );

        // The captured `yggdrasilctl` value on the same link, `21-admin.md:421`.
        assert_eq!(
            go_latency(Some(at(52_000_000)), Some(at(0))),
            Some(Duration::from_nanos(52_000_000))
        );

        // And rounding on a large delta, so the `+ 5_000` cannot be dropped
        // without this noticing: 50.004 ms rounds to 50.00 ms, 50.005 ms to 50.01.
        assert_eq!(
            go_latency(Some(at(50_004_999)), Some(at(0))),
            Some(Duration::from_nanos(50_000_000))
        );
        assert_eq!(
            go_latency(Some(at(50_005_000)), Some(at(0))),
            Some(Duration::from_nanos(50_010_000)),
            "half a quantum rounds up, not down"
        );
    }

    /// The delta is measured **between the two stored timestamps**, so it is a
    /// property of the pair and not of when the query happens.
    ///
    /// Go reads `peer.srrt.Sub(peer.srst)` at *query* time
    /// (`ironwood/network/debug.go:85`), so the reported number does not drift
    /// between two calls — which is a difference from the naive "measure the age of
    /// the last reply" reading, and the reason this takes two instants rather than
    /// one and a clock.
    #[test]
    fn the_delta_does_not_drift_with_the_query_time() {
        let (srrt, srst) = (at(20_000_000), at(0));
        let first = go_latency(Some(srrt), Some(srst));
        // A clock reading, and time passing, must not appear in the answer.
        let _later = at(900_000_000);
        assert_eq!(go_latency(Some(srrt), Some(srst)), first);
        assert_eq!(first, Some(Duration::from_millis(20)));
    }
}
