//! Link driver: register / maintain / dispatch / serve slices over a caller-owned `LinkSet`.
//! Orchestrates the composed tables; per-link send clocks live in the set.

use std::time::{Duration, Instant};

use crate::address::KEY_LEN;
use crate::error::Error;
use crate::frame::{FrameType, KEEPALIVE_DELAY};
use crate::link::{Link, LinkSet};
use crate::peer::PeerState;
use crate::router::{MAINTENANCE_INTERVAL, Router, UNKNOWN_LATENCY};
use crate::tree::{Announce, SigReq, SigRes};

impl Router {
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
        // Keep the RTT estimate across reconnects; everything else is fresh
        // per link (Go resets per-link state the same way).
        let lag = self
            .tree
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
            kind: conn.peer_kind(),
        };
        // One registration per link (callers register once, then serve in
        // slices): open SigReq, bloom, and replay of already-sent announces
        // for a known key (Go `addPeer` replays to new links the same way).
        self.tree.peers.insert(peer_key, peer);
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
        let replay: Vec<Announce> = self
            .tree
            .sent
            .get(&peer_key)
            .map(|s| {
                s.iter()
                    .filter_map(|k| self.tree.infos.get(k).map(|i| i.announce(*k)))
                    .collect()
            })
            .unwrap_or_default();
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
                // Quiet slice: keep the link alive for long lookups.
                Err(_) => {
                    self.keepalive_if_idle(links, conn_peer).await?;
                }
            }
            let want = addr.0;
            let want_subnet = addr.0[0] == crate::address::NODE_PREFIX | crate::address::SUBNET_BIT;
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
            self.rumor_lookup(links, peer_key, dest).await?;
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
    async fn keepalive_if_idle(
        &self,
        links: &mut LinkSet<'_>,
        peer: [u8; KEY_LEN],
    ) -> Result<(), Error> {
        if links.idle_for(&peer) >= KEEPALIVE_DELAY {
            links.write(peer, FrameType::KeepAlive, &[]).await?;
        }
        Ok(())
    }

    /// Handle one inbound frame: router protocol plus a lazy keepalive
    /// reply for every non-keepalive type (Go `peerMonitor` semantics).
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
                self.keepalive_if_idle(links, conn_peer).await?;
            }
            FrameType::SigRes => {
                if let Ok((res, n)) = SigRes::decode(payload)
                    && n == payload.len()
                    && res.check(&self.pubkey, &conn_peer)
                {
                    self.handle_response(conn_peer, res);
                }
                self.keepalive_if_idle(links, conn_peer).await?;
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
                        self.tree.announces_sent += 1;
                    }
                }
                self.keepalive_if_idle(links, conn_peer).await?;
            }
            FrameType::BloomFilter => {
                let _ = self.bloom_handle(conn_peer, payload);
                self.keepalive_if_idle(links, conn_peer).await?;
            }
            FrameType::PathLookup => {
                if let Ok(lookup) = crate::pathfind::PathLookup::decode_exact(payload) {
                    self.handle_lookup(links, conn_peer, conn_peer, &lookup)
                        .await?;
                }
                self.keepalive_if_idle(links, conn_peer).await?;
            }
            FrameType::PathNotify => {
                if let Ok(notify) = crate::pathfind::PathNotify::decode_exact(payload)
                    && notify.check()
                {
                    self.handle_notify(links, conn_peer, &notify).await?;
                }
                self.keepalive_if_idle(links, conn_peer).await?;
            }
            FrameType::PathBroken => {
                if let Ok(broken) = crate::pathfind::PathBroken::decode_exact(payload) {
                    self.handle_broken(links, conn_peer, &broken).await?;
                }
                self.keepalive_if_idle(links, conn_peer).await?;
            }
            FrameType::Traffic => {
                if let Ok(tr) = crate::traffic::Traffic::decode(payload) {
                    self.handle_inbound_traffic(links, conn_peer, &tr).await?;
                }
                self.keepalive_if_idle(links, conn_peer).await?;
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
        links: &mut LinkSet<'_>,
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
        links: &mut LinkSet<'_>,
        hold_for: Option<Duration>,
        outgoing: &mut Vec<([u8; KEY_LEN], Vec<u8>)>,
    ) -> Result<(), Error> {
        // Previously failed payloads go first (at-least-once across links).
        outgoing.splice(..0, std::mem::take(&mut self.sess.resend));
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
            let timeout = end
                .map(|e| e.saturating_duration_since(now))
                .unwrap_or(MAINTENANCE_INTERVAL)
                .min(MAINTENANCE_INTERVAL);
            if links.peers().is_empty() {
                // No links: sleep the budget instead of spinning — an
                // empty read/dispatch loop has no await point that parks.
                tokio::time::sleep(timeout).await;
                continue;
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
                    // A dead link is evicted, not fatal: remaining links
                    // keep serving (single-link callers see an empty set
                    // below and get the last error, preserving the old
                    // `serve` contract).
                    Ok(Err(e)) => {
                        links.remove(&peer);
                        if links.is_empty() {
                            return Err(e);
                        }
                    }
                    // Quiet slice: top up links idle past a full tick so
                    // the peer's liveness monitor never starves, even when
                    // no frames arrive to answer (Go sends on the same
                    // 1s timer instead of per-frame).
                    Err(_) => {
                        self.keepalive_if_idle(links, peer).await?;
                    }
                }
            }
        }
        Ok(())
    }
}
