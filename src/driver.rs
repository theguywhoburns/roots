//! Link driver: register / maintain / dispatch / serve slices over a caller-owned `LinkSet`.
//! Orchestrates the composed tables; per-link send clocks live in the set.

use std::time::{Duration, Instant};

use crate::address::KEY_LEN;
use crate::error::{CoreError, Error};
use crate::frame::{FrameType, KEEPALIVE_DELAY};
use crate::link::{Link, LinkSet};
use crate::peer::PeerState;
use crate::router::{MAINTENANCE_INTERVAL, Router, UNKNOWN_LATENCY};
use crate::tree::{Announce, SigReq, SigRes};

/// What a payload handed to [`Router::send_or_resolve`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Left now: we already knew the key that owns the address and held a
    /// live path to it, so the payload went out without a lookup.
    Sent,
    /// Held: a lookup is out and this destination's one payload waits for the
    /// notify that names the key.
    Queued,
}

impl Router {
    /// Register a peer after the link handshake: open SigReq, bloom, and
    /// replay of already-sent announces (Go `addPeer`). Call ONCE per link
    /// (not per serve slice): the peer answers every SigReq and replays
    /// are sent-map-gated, so repeats look like a reconnect storm.
    ///
    /// `id` identifies this one connection, because a node key no longer does:
    /// two links to one key are two peers to Go, each with its own lag and
    /// round trip (`router.go:135-136`, `peers.go:47-62`). The key-level port
    /// and open request are shared, which is what ironwood keys by `publicKey`.
    pub async fn register(
        &mut self,
        conn: &mut dyn Link,
        peer_key: [u8; KEY_LEN],
        id: crate::link::LinkId,
    ) -> Result<(), Error> {
        // Reuse the link port for a known key (Go keeps one port per key
        // across reconnects); only brand-new keys allocate.
        let port = self
            .tree
            .peers
            .get(&peer_key)
            .map(|p| p.port)
            .unwrap_or_else(|| {
                let q = self.tree.next_port;
                self.tree.next_port += 1;
                q
            });
        let order = self.tree.peer_order;
        self.tree.peer_order += 1;
        // Reuse the open request for a known key (Go re-sends the stored
        // req on re-add; minting a fresh req per serve call looks like a
        // reconnect storm and gets answered as one).
        let req = self
            .tree
            .peers
            .get(&peer_key)
            .map(|p| p.req)
            .unwrap_or_else(|| self.new_req());
        // A new link starts with no round trip, exactly like Go's fresh `*peer`
        // (`r.lags[p] = routerUnknownLatency`, `router.go:136`). Carrying the
        // old estimate over to the new connection would report a dead socket's
        // latency as this one's.
        let link = crate::peer::LinkState {
            peer: peer_key,
            responded: false,
            lag: UNKNOWN_LATENCY,
            sent_at: Some(Instant::now()),
            srrt: None,
            prio: conn.priority(),
            order,
            kind: conn.peer_kind(),
        };
        // Whether the key was already known decides the replay: Go replays
        // `r.sent[pk]` only on the `else` branch of "is this key in r.peers"
        // (`router.go:120-130`), so a first link to a node has nothing to
        // replay and must not be sent the announces we have not made yet.
        let known = self.tree.peers.contains_key(&peer_key);
        // One registration per link (callers register once, then serve in
        // slices): open SigReq, bloom, and replay of already-sent announces
        // for a known key (Go `addPeer` replays to new links the same way).
        self.tree.peers.insert(peer_key, PeerState { port, req });
        self.tree.links.insert(id, link);
        self.tree.sent.entry(peer_key).or_default();
        self.bloom_add_peer(peer_key);
        // Advertise our (initially empty) bloom immediately, like Go.
        let bloom_bytes = self
            .bloom
            .send
            .get(&peer_key)
            .map(|b| b.encode())
            .unwrap_or_default();
        conn.write_frame(FrameType::BloomFilter, &bloom_bytes)
            .await?;
        let mut out = Vec::new();
        req.encode(&mut out);
        conn.write_frame(FrameType::SigReq, &out).await?;
        // Replay anything already announced to this key over older links.
        let replay: Vec<Announce> = if known {
            self.tree
                .sent
                .get(&peer_key)
                .map(|s| {
                    s.iter()
                        .filter_map(|k| self.tree.infos.get(k).map(|i| i.announce(*k)))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        for ann in replay {
            let mut buf = Vec::new();
            ann.encode(&mut buf);
            conn.write_frame(FrameType::Announce, &buf).await?;
            self.tree.announces_sent += 1;
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
        links: &mut LinkSet,
        conn: crate::link::LinkId,
        addr: &crate::address::Address,
        timeout: Duration,
    ) -> Result<[u8; KEY_LEN], Error> {
        // A frame can only arrive on a live link, so `conn` must be in the set.
        // Checking it here turns a stale handle into a clear error instead of a
        // panic in the read below.
        if links.peer_of(conn).is_none() {
            return Err(Error::Core(CoreError::NoLink));
        }
        let partial = crate::address::lookup_key_for_addr(addr);
        let end = tokio::time::Instant::now() + timeout;
        let mut last_maintain = tokio::time::Instant::now();
        while tokio::time::Instant::now() < end {
            // Via the rumor path (creates the pending entry that lets us
            // accept the arriving notify), like Go's `SendLookup`.
            self.rumor_lookup(links, partial).await?;
            // Keep the tree alive while resolving (same tick as serve).
            let now = tokio::time::Instant::now();
            if now.duration_since(last_maintain) >= MAINTENANCE_INTERVAL {
                last_maintain = now;
                self.maintain(links).await?;
            }
            let remaining = end.saturating_duration_since(tokio::time::Instant::now());
            let wait = remaining.min(Duration::from_secs(2));
            let frame = tokio::time::timeout(wait, links.read_frame(conn)).await;
            match frame {
                Ok(Ok((ftype, payload))) => {
                    self.frames[ftype as usize] += 1;
                    self.dispatch_frame(links, conn, ftype, &payload).await?;
                }
                Ok(Err(e)) => return Err(e),
                // Quiet slice: keep the link alive for long lookups.
                Err(_) => {
                    self.keepalive_if_idle(links, conn).await?;
                }
            }
            let want = addr.0;
            let want_subnet = addr.is_subnet();
            if let Some(k) = self
                .path
                .entries
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
        Err(Error::Core(CoreError::Timeout))
    }

    /// Send `payload` for `dest` now, or hold it until a DHT notify names the
    /// key that owns that address.
    ///
    /// This is resolve-and-hold, the library half: a caller with a packet to
    /// hand over never waits for a lookup, so a device write cannot block the
    /// loop. Go's keyStore keeps the held copy per address or subnet
    /// (`ipv6rwc.go:84-102` for a node address, `ipv6rwc.go:112-130` for a
    /// subnet) and writes it out from the path-notify callback
    /// (`ipv6rwc.go:66-68` → `update`, `ipv6rwc.go:149-162`). Ironwood keeps
    /// its own single slot per destination, `rumors[xform].traffic`, and
    /// flushes that in `_handleNotify` (`pathfinder.go:145-149` then
    /// `pathfinder.go:154-159`). We use the ironwood slot, which
    /// [`Router::handle_notify`] already drains (`pathfind.rs:453-461`), so
    /// each destination has one held copy and one flush, never two.
    ///
    /// `dest` is a node address or a routed subnet, and
    /// [`crate::address::lookup_key_for_addr`] picks the lossy key for each —
    /// Go's split at `ipv6rwc.go:306-311`, where an address that validates
    /// goes to `sendToAddress` and one that only validates as a subnet goes to
    /// `sendToSubnet`.
    ///
    /// `via` must name a live link. The lookup does not leave on it: Go floods
    /// a lookup over the bloom's on-tree set and names no connection
    /// (`_sendLookup`, `pathfinder.go:27-42`), so `via` is the caller's
    /// liveness check, the same one [`Router::resolve`] makes before it reads
    /// a frame. The payload that follows the notify picks its own next hop
    /// through the pathfinder.
    ///
    /// `payload` is an **application payload** — a whole IP packet, for the TUN —
    /// and it goes out as a **session message**, not as the traffic frame's
    /// payload. Those are different layers, and the difference is the whole
    /// reason a TUN works:
    ///
    /// - Ironwood's layering is app → **session** → **pathfinder** → link:
    ///   `encrypted.PacketConn.WriteTo` → `sessions.writeTo` →
    ///   `network.PacketConn.WriteTo` (`encrypted/packetconn.go:66-84`, then
    ///   `network/packetconn.go:72-93`). Our `session_send` → `net_send` →
    ///   `pathfinder_send` is exactly that chain.
    /// - So the IP packet is **box-sealed against the peer's session key first**,
    ///   and only the sealed blob is a traffic frame's payload. `ipv6rwc` calls
    ///   `core.WriteTo` in both directions (`ipv6rwc.go:82`, `:307`), and
    ///   `Core.WriteTo` prepends the type byte to the *plaintext* before handing
    ///   it down (`core.go:210-216`).
    ///
    /// This reached **below** the session layer at first, straight to
    /// `pathfinder_send`, and the TUN silently carried nothing: the frame left
    /// the sender, the counter moved, and the far end's `handle_session_bytes`
    /// dropped it because a raw IP packet is not a session message. Measured as
    /// 100% ICMP loss over a link that was `up: true` on both ends. Two things
    /// were missing at once — the type byte *and* the seal — and either alone is
    /// fatal, which is why the empty test suite did not catch it and the real
    /// device did.
    ///
    /// The DHT lookup keeps its one job, which is Go's: learn the **key** behind
    /// an address. Go holds the packet against the address in the key store
    /// (`ipv6rwc.go:84-102`) and the path-notify callback writes it out through
    /// `core.WriteTo` (`ipv6rwc.go:66-68`) — never through a traffic frame.
    pub async fn send_or_resolve(
        &mut self,
        links: &mut LinkSet,
        via: crate::link::LinkId,
        dest: &crate::address::Address,
        payload: Vec<u8>,
    ) -> Result<Route, Error> {
        if links.peer_of(via).is_none() {
            return Err(Error::Core(CoreError::NoLink));
        }
        // No type byte here. `session_send` is the thing that adds it
        // (`session_send_kind(..., PACKET_TYPE_TRAFFIC, ...)`, `session.rs:400`),
        // which is where Go adds it too (`core.go:210-216`) and why the payload
        // is passed on as it arrived. Putting one on *here* as well is a
        // plausible-looking double prepend that the far end answers by delivering
        // a packet whose first byte is `0x01` instead of `0x60` — measured, and
        // the kernel drops it as malformed.
        let msg = payload;
        if let Some(key) = self.key_for_addr(dest) {
            // A notify or a session already named the key, so no lookup:
            // `session_send` boxes it now, or holds it behind an init if the
            // session is not up yet (`ipv6rwc.go:82` → `core.WriteTo`).
            self.session_send(links, key, msg).await?;
            return Ok(Route::Sent);
        }
        // No key yet. The lossy key is all an address gives us and a session
        // cannot be opened to one, so this is a *lookup*, not a send. One slot
        // per destination, overwriting whatever was held — ironwood's
        // `rumors[xform].traffic` (`pathfinder.go:211-222`), and Go's key store
        // does the same (`ipv6rwc.go:88-92`).
        let lossy = crate::address::lookup_key_for_addr(dest);
        self.hold_for_lookup(links, lossy, msg).await?;
        Ok(Route::Queued)
    }

    /// The full key that owns `addr`, from the keys a notify or a session
    /// taught us. A node address matches a key's whole address and a routed
    /// subnet matches its /64 prefix, which is the `sendToAddress` /
    /// `sendToSubnet` split again (`ipv6rwc.go:306-311`).
    ///
    /// Go's table is `keyStore.addrToInfo` / `subnetToInfo`, filled by the
    /// path-notify callback and dropped after `keyStoreTimeout`
    /// (`ipv6rwc.go:141-157`, `ipv6rwc.go:20`). Ours is `path.entries` plus
    /// `sess.sessions`: both are keyed by full key, and a session can outlive
    /// the path entry that opened it.
    fn key_for_addr(&self, addr: &crate::address::Address) -> Option<[u8; KEY_LEN]> {
        let want = addr.0;
        let want_subnet = addr.is_subnet();
        self.path
            .entries
            .keys()
            .chain(self.sess.sessions.keys())
            .copied()
            .find(|k| {
                crate::address::addr_for_key(k).0 == want
                    || (want_subnet
                        && crate::address::subnet_for_key(k).0
                            == want[..crate::address::SUBNET_LEN])
            })
    }

    /// One maintenance tick: expire, fix parent, send announces.
    ///
    /// Takes no peer: Go's `_doMaintenance` is a single global tick
    /// (`router.go:89-100`), and the two sends it drives iterate the whole peer
    /// table themselves — `_sendAnnounces` walks `r.sent` and fans out to every
    /// link of each key (`router.go:320-378`), `_sendReqs` walks `r.peers`
    /// (`router.go:186-197`). Calling this per link, as an earlier version did,
    /// sent each announce once per connection.
    pub async fn maintain(&mut self, links: &mut LinkSet) -> Result<(), Error> {
        self.expire();
        self.fix(links).await?;
        self.send_announces(links).await?;
        self.bloom_maintenance(links).await?;
        self.expire_ephemeral();
        // Re-drive lookups for still-pending rumors (a lookup sent before
        // blooms converged is dropped, not queued — Go relies on the app
        // to retransmit; without an app layer we retry here, throttled).
        // Resolved when some path shares the rumor's transformed key.
        let pending: Vec<[u8; KEY_LEN]> = self
            .path
            .rumors
            .iter()
            .filter(|(x, r)| {
                r.pending.is_some()
                    && !self
                        .path
                        .entries
                        .keys()
                        .any(|k| crate::bloom::xkey(k) == **x)
            })
            .map(|(_, r)| r.dest)
            .collect();
        for dest in pending {
            self.rumor_lookup(links, dest).await?;
        }
        Ok(())
    }

    /// Drop expired paths, rumors, session buffers, and idle sessions.
    pub(crate) fn expire_ephemeral(&mut self) {
        let now = Instant::now();
        self.path.entries.retain(|_, e| e.deadline > now);
        self.path.rumors.retain(|_, r| r.deadline > now);
        self.sess.bufs.retain(|_, b| b.deadline > now);
        self.sess
            .sessions
            .retain(|_, (_, active)| *active + crate::session::SESSION_TIMEOUT > now);
    }

    /// Keepalive reply for an inbound frame, Go `peerMonitor` style: only
    /// when we sent nothing to this link for a full tick. Any outbound
    /// frame (announce, SigRes, session data) already proves liveness,
    /// so per-frame replies would be pure chatter.
    ///
    /// Per **link**, because the send clock is: Go's keepalive timer lives on
    /// `peer` (`peers.go:117-137`), so a busy second connection never makes an
    /// idle first one look answered.
    async fn keepalive_if_idle(
        &self,
        links: &mut LinkSet,
        conn: crate::link::LinkId,
    ) -> Result<(), Error> {
        if links.idle_for(conn) >= KEEPALIVE_DELAY {
            links.write(conn, FrameType::KeepAlive, &[]).await?;
        }
        Ok(())
    }

    /// Soft send through the set to a next hop we may have no link for.
    /// Go drops those frames in silence (`router.go` `peers[key]` lookup); we
    /// drop them too, but count it, because a forwarding hole nobody can see
    /// is indistinguishable from a working mesh.
    pub(crate) async fn write_via(
        &mut self,
        links: &mut LinkSet,
        next: crate::link::LinkId,
        ftype: FrameType,
        buf: &[u8],
    ) -> Result<(), Error> {
        if links.peer_of(next).is_none() {
            self.dropped_no_link += 1;
            return Ok(());
        }
        links.write_via(next, ftype, buf).await?;
        Ok(())
    }

    /// Must a failed serve step abort the whole serve? No, if it was one
    /// link's socket: `LinkSet::send` retires a link that refuses a frame,
    /// so a link error only means the set shrank, and the survivors keep
    /// serving. It is fatal when nothing is left to serve — that preserves
    /// the single-link `serve` contract callers redial on. Anything else
    /// (a protocol violation, a bad signature) stays fatal. Go needs no such
    /// rule: every peer owns a reader goroutine (`peers.go:228`), so a dead
    /// link cannot abort a live one.
    pub(crate) fn fatal_link_error(links: &LinkSet, e: &Error) -> bool {
        // `is_link` rather than an open-coded match, so that adding an error
        // variant cannot leave this one behind. It is the whole of what the
        // old `matches!(e, Error::Io(_) | Error::NoLink)` said, and the
        // `BadUri`/`BadMaxBackoff` arms in `is_link` are the interesting part:
        // a URI that will not parse is not a dead link, so a misconfigured peer
        // must not be redialed forever.
        !e.is_link() || links.is_empty()
    }

    /// Handle one inbound frame: router protocol plus a lazy keepalive
    /// reply for every non-keepalive type (Go `peerMonitor` semantics).
    ///
    /// `conn` is the link the frame arrived on. Go threads the `*peer` through
    /// this whole path (`handleRequest(from, p, req)`, `peers.go:318`), and the
    /// distinction is load-bearing: a `SigRes` goes back down the link that
    /// asked, a keepalive is judged against that link's own send clock, and the
    /// per-link lag is updated on the connection that answered.
    pub(crate) async fn dispatch_frame(
        &mut self,
        links: &mut LinkSet,
        conn: crate::link::LinkId,
        ftype: FrameType,
        payload: &[u8],
    ) -> Result<(), Error> {
        // The node key behind this link. A frame can only arrive on a link the
        // set still holds, so this cannot be `None`; treating it as such would
        // mean silently dropping a frame we have already read.
        let Some(conn_peer) = links.peer_of(conn) else {
            return Ok(());
        };
        match ftype {
            FrameType::KeepAlive | FrameType::Dummy => {}
            FrameType::SigReq => {
                if let Ok((req, n)) = SigReq::decode(payload)
                    && n == payload.len()
                {
                    self.handle_request(links, conn, conn_peer, req).await?;
                }
                self.keepalive_if_idle(links, conn).await?;
            }
            FrameType::SigRes => {
                if let Ok((res, n)) = SigRes::decode(payload)
                    && n == payload.len()
                    && res.check(&self.pubkey, &conn_peer)
                {
                    self.handle_response(conn, conn_peer, res);
                }
                self.keepalive_if_idle(links, conn).await?;
            }
            FrameType::Announce => {
                if let Ok(ann) = Announce::decode_exact(payload)
                    && ann.check()
                {
                    let reply = self.handle_announce(links, conn_peer, &ann);
                    if let Some(better) = reply {
                        let mut buf = Vec::new();
                        better.encode(&mut buf);
                        // Back down the link that sent it, as Go does
                        // (`p.sendAnnounce(r, ann)`, `peers.go:354-356`).
                        links.write(conn, FrameType::Announce, &buf).await?;
                        self.tree.announces_sent += 1;
                    }
                }
                self.keepalive_if_idle(links, conn).await?;
            }
            FrameType::BloomFilter => {
                let _ = self.bloom_handle(conn_peer, payload);
                self.keepalive_if_idle(links, conn).await?;
            }
            FrameType::PathLookup => {
                if let Ok(lookup) = crate::pathfind::PathLookup::decode_exact(payload) {
                    self.handle_lookup(links, conn_peer, &lookup).await?;
                }
                self.keepalive_if_idle(links, conn).await?;
            }
            FrameType::PathNotify => {
                if let Ok(notify) = crate::pathfind::PathNotify::decode_exact(payload)
                    && notify.check()
                {
                    self.handle_notify(links, &notify).await?;
                }
                self.keepalive_if_idle(links, conn).await?;
            }
            FrameType::PathBroken => {
                if let Ok(broken) = crate::pathfind::PathBroken::decode_exact(payload) {
                    self.handle_broken(links, &broken).await?;
                }
                self.keepalive_if_idle(links, conn).await?;
            }
            FrameType::Traffic => {
                if let Ok(tr) = crate::traffic::Traffic::decode(payload) {
                    self.handle_inbound_traffic(links, &tr).await?;
                }
                self.keepalive_if_idle(links, conn).await?;
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
    ///
    /// The `links` set is caller-owned and reused across slices: per-link
    /// state (notably last-send times for lazy keepalives) must survive
    /// from one slice to the next, so rebuilding the set per slice will
    /// silently stop keepalives and get the link killed.
    pub async fn serve(
        &mut self,
        links: &mut LinkSet,
        hold_for: Option<Duration>,
        outgoing: &mut Vec<([u8; KEY_LEN], Vec<u8>)>,
    ) -> Result<(), Error> {
        self.serve_links(links, hold_for, outgoing).await
    }

    /// Serve every link in the set through one router: per-link maintain,
    /// shared session outbox, frames dispatched with their arrival peer.
    /// Single-link `serve` is this with a one-entry set; multi-peer apps
    /// register each link once, then slice this.
    pub async fn serve_links(
        &mut self,
        links: &mut LinkSet,
        hold_for: Option<Duration>,
        outgoing: &mut Vec<([u8; KEY_LEN], Vec<u8>)>,
    ) -> Result<(), Error> {
        // Previously failed payloads go first (at-least-once across links).
        outgoing.splice(..0, std::mem::take(&mut self.sess.resend));
        let end = hold_for.map(|h| tokio::time::Instant::now() + h);
        let mut last_maintain = tokio::time::Instant::now();
        if let Err(e) = self.maintain(links).await
            && Self::fatal_link_error(links, &e)
        {
            return Err(e);
        }
        loop {
            let now = tokio::time::Instant::now();
            if let Some(end) = end
                && now >= end
            {
                break;
            }
            let timeout = end
                .map(|e| e.saturating_duration_since(now))
                .unwrap_or(MAINTENANCE_INTERVAL)
                .min(MAINTENANCE_INTERVAL);
            let ids = links.ids();
            if ids.is_empty() {
                // No links: sleep the budget instead of spinning — an
                // empty read/dispatch loop has no await point that parks.
                tokio::time::sleep(timeout).await;
                continue;
            }
            for (dest, msg) in std::mem::take(outgoing) {
                // Outbox sends are link-agnostic (the pathfinder picks the next
                // hop); the peer key only scopes per-link state refreshes.
                if let Err(e) = self.session_send(links, dest, msg).await {
                    if Self::fatal_link_error(links, &e) {
                        return Err(e);
                    }
                    // `session_send_inner` already put the payload back in
                    // `resend`, so the next slice retries it on a survivor.
                    break;
                }
            }
            if now.duration_since(last_maintain) >= MAINTENANCE_INTERVAL {
                last_maintain = now;
                if let Err(e) = self.maintain(links).await
                    && Self::fatal_link_error(links, &e)
                {
                    return Err(e);
                }
            }
            // Drain every link. A single link blocks for the whole budget
            // (exact old `serve` timing); several links take short slices
            // each so one quiet link never starves the rest.
            let slice = if links.len() > 1 {
                timeout.min(Duration::from_millis(100))
            } else {
                timeout
            };
            for id in links.ids() {
                let frame = tokio::time::timeout(slice, links.read_frame(id)).await;
                match frame {
                    Ok(Ok((ftype, payload))) => {
                        self.frames[ftype as usize] += 1;
                        if let Err(e) = self.dispatch_frame(links, id, ftype, &payload).await {
                            if Self::fatal_link_error(links, &e) {
                                return Err(e);
                            }
                            // A reply this frame provoked hit a dead link:
                            // that link is gone, abandon the rest of this
                            // slice and re-plan from the survivors.
                            break;
                        }
                    }
                    // A dead link is evicted, not fatal: remaining links
                    // keep serving (single-link callers see an empty set
                    // below and get the last error, preserving the old
                    // `serve` contract).
                    Ok(Err(e)) => {
                        // The removed link is dropped here, which closes its
                        // socket; the caller owns nothing left to reclaim.
                        // Its per-link tree state goes with it, or the router
                        // would keep routing to a connection that is gone.
                        let _ = links.remove(id);
                        self.tree.links.remove(&id);
                        if links.is_empty() {
                            return Err(e);
                        }
                    }
                    // Quiet slice: top up links idle past a full tick so the
                    // peer's liveness monitor never starves, even when no
                    // frames arrive to answer (Go sends on the same 1 s timer
                    // instead of per frame).
                    Err(_) => {
                        if let Err(e) = self.keepalive_if_idle(links, id).await {
                            if Self::fatal_link_error(links, &e) {
                                return Err(e);
                            }
                            // The link vanished between the snapshot and the
                            // keepalive; the next slice works off the set.
                            continue;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
