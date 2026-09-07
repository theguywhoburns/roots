//! Pathfinder wire types. Ports of `ironwood/network/pathfinder.go`:
//! `pathLookup`, `pathNotifyInfo`, `pathNotify`, `pathBroken`.
//!
//! Layouts (uvarints are LEB128, paths are zero-terminated port lists):
//! - lookup: `source[32] + dest[32] + path`
//! - notify info: `seq + path + sig[64]`, signed by source over `seq + path`
//! - notify: `path + watermark + source[32] + dest[32] + info`
//! - broken: `path + watermark + source[32] + dest[32]`

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::address::KEY_LEN;
use crate::error::Error;
use crate::frame::{FrameType, append_path, append_uvarint, read_uvarint, split_path};
use crate::link::LinkSet;

/// Learned source route to a node (Go `pathInfo`, timers as instants).
#[derive(Debug, Clone)]
pub(crate) struct PathEntry {
    pub path: Vec<u64>,
    pub seq: u64,
    pub req_at: Option<std::time::Instant>,
    pub deadline: std::time::Instant,
    pub broken: bool,
}

/// Pending destination lookup (Go `pathRumor`, keyed by transformed key —
/// lookups for partial keys and notifies from full keys rendezvous here).
#[derive(Debug, Clone)]
pub(crate) struct RumorEntry {
    /// Lookup target as requested (partial or full key).
    pub dest: [u8; KEY_LEN],
    pub send_at: Option<std::time::Instant>,
    pub deadline: std::time::Instant,
    pub pending: Option<Vec<u8>>,
}

/// How long a learned path is kept without inbound traffic (Go `pathTimeout`).
pub const PATH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Minimum gap between lookups for one destination (Go `pathThrottle`).
pub const PATH_THROTTLE: std::time::Duration = std::time::Duration::from_secs(1);

/// Source-routing table: learned paths, pending DHT rumors, and our latest
/// signed notify. Owned by [`crate::router::Router`].
pub(crate) struct PathState {
    pub(crate) entries: std::collections::HashMap<[u8; KEY_LEN], PathEntry>,
    pub(crate) rumors: std::collections::HashMap<[u8; KEY_LEN], RumorEntry>,
    pub(crate) notify: NotifyInfo,
}

impl Default for PathState {
    fn default() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            rumors: std::collections::HashMap::new(),
            notify: NotifyInfo {
                seq: 0,
                path: Vec::new(),
                sig: [0u8; 64],
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathLookup {
    pub source: [u8; KEY_LEN],
    pub dest: [u8; KEY_LEN],
    pub from: Vec<u64>,
}

impl PathLookup {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
        append_path(out, &self.from);
    }

    pub fn decode_exact(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 2 * KEY_LEN {
            return Err(Error::InvalidLength);
        }
        let mut source = [0u8; KEY_LEN];
        let mut dest = [0u8; KEY_LEN];
        source.copy_from_slice(&buf[..KEY_LEN]);
        dest.copy_from_slice(&buf[KEY_LEN..2 * KEY_LEN]);
        let (from, _) = split_path(&buf[2 * KEY_LEN..]).ok_or(Error::InvalidLength)?;
        Ok(Self { source, dest, from })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyInfo {
    pub seq: u64,
    pub path: Vec<u64>,
    pub sig: [u8; 64],
}
impl NotifyInfo {
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        let mut out = Vec::new();
        append_uvarint(&mut out, self.seq);
        append_path(&mut out, &self.path);
        out
    }

    pub fn sign(&mut self, key: &SigningKey) {
        self.sig = key.sign(&self.bytes_for_sig()).to_bytes();
    }

    pub fn check(&self, source: &[u8; KEY_LEN]) -> bool {
        VerifyingKey::from_bytes(source)
            .and_then(|k| {
                k.verify_strict(
                    &self.bytes_for_sig(),
                    &ed25519_dalek::Signature::from_bytes(&self.sig),
                )
            })
            .is_ok()
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        append_uvarint(out, self.seq);
        append_path(out, &self.path);
        out.extend_from_slice(&self.sig);
    }

    /// Decode, returning value + bytes consumed (caller enforces exactness).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Error> {
        let (seq, n) = read_uvarint(buf).ok_or(Error::InvalidLength)?;
        let (path, m) = split_path(&buf[n..]).ok_or(Error::InvalidLength)?;
        let rest = &buf[n + m..];
        if rest.len() < 64 {
            return Err(Error::InvalidLength);
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&rest[..64]);
        Ok((Self { seq, path, sig }, n + m + 64))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathNotify {
    pub path: Vec<u64>,
    pub watermark: u64,
    pub source: [u8; KEY_LEN],
    pub dest: [u8; KEY_LEN],
    pub info: NotifyInfo,
}

impl PathNotify {
    pub fn check(&self) -> bool {
        self.info.check(&self.source)
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        append_path(out, &self.path);
        append_uvarint(out, self.watermark);
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
        self.info.encode(out);
    }

    pub fn decode_exact(buf: &[u8]) -> Result<Self, Error> {
        let (path, n) = split_path(buf).ok_or(Error::InvalidLength)?;
        let (watermark, m) = read_uvarint(&buf[n..]).ok_or(Error::InvalidLength)?;
        let rest = &buf[n + m..];
        if rest.len() < 2 * KEY_LEN {
            return Err(Error::InvalidLength);
        }
        let mut source = [0u8; KEY_LEN];
        let mut dest = [0u8; KEY_LEN];
        source.copy_from_slice(&rest[..KEY_LEN]);
        dest.copy_from_slice(&rest[KEY_LEN..2 * KEY_LEN]);
        let (info, k) = NotifyInfo::decode(&rest[2 * KEY_LEN..])?;
        if k != rest[2 * KEY_LEN..].len() {
            return Err(Error::InvalidLength);
        }
        Ok(Self {
            path,
            watermark,
            source,
            dest,
            info,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathBroken {
    pub path: Vec<u64>,
    pub watermark: u64,
    pub source: [u8; KEY_LEN],
    pub dest: [u8; KEY_LEN],
}

impl PathBroken {
    pub fn encode(&self, out: &mut Vec<u8>) {
        append_path(out, &self.path);
        append_uvarint(out, self.watermark);
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
    }

    pub fn decode_exact(buf: &[u8]) -> Result<Self, Error> {
        let (path, n) = split_path(buf).ok_or(Error::InvalidLength)?;
        let (watermark, m) = read_uvarint(&buf[n..]).ok_or(Error::InvalidLength)?;
        let rest = &buf[n + m..];
        if rest.len() != 2 * KEY_LEN {
            return Err(Error::InvalidLength);
        }
        let mut source = [0u8; KEY_LEN];
        let mut dest = [0u8; KEY_LEN];
        source.copy_from_slice(&rest[..KEY_LEN]);
        dest.copy_from_slice(&rest[KEY_LEN..]);
        Ok(Self {
            path,
            watermark,
            source,
            dest,
        })
    }
}
impl crate::router::Router {
    /// Coords (root-to-node ports) for any known node (Go `_getRootAndPath`).
    pub(crate) fn root_path_for(&self, dest: &[u8; KEY_LEN]) -> Option<Vec<u64>> {
        let mut ports = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut next = *dest;
        loop {
            if !seen.insert(next) {
                return None; // loop
            }
            let info = self.tree.infos.get(&next)?;
            if next == info.parent {
                break; // root: no self port
            }
            ports.push(info.res.port);
            next = info.parent;
        }
        ports.reverse();
        Some(ports)
    }

    pub(crate) fn root_path(&self) -> Option<Vec<u64>> {
        let me = self.pubkey;
        self.root_path_for(&me)
    }

    fn coords_dist(dest_path: &[u64], key_path: &[u64]) -> u64 {
        let common = dest_path
            .iter()
            .zip(key_path.iter())
            .take_while(|(a, b)| a == b)
            .count();
        (key_path.len() + dest_path.len() - 2 * common) as u64
    }

    /// Greedy next hop toward tree-space `path` (Go `_lookup`), updating the
    /// watermark to our distance when we forward.
    pub(crate) fn greedy_next(&self, path: &[u64], watermark: &mut u64) -> Option<[u8; KEY_LEN]> {
        let mut best_dist = u64::MAX;
        if let Some(sp) = self.root_path() {
            let d = Self::coords_dist(path, &sp);
            if d < *watermark {
                best_dist = d;
                *watermark = d;
            } else {
                return None;
            }
        }
        let mut keys: Vec<[u8; KEY_LEN]> = self.tree.peers.keys().copied().collect();
        keys.sort();
        let mut cands: Vec<[u8; KEY_LEN]> = Vec::new();
        for k in &keys {
            if let Some(kp) = self.root_path_for(k)
                && Self::coords_dist(path, &kp) < best_dist
            {
                cands.push(*k);
            }
        }
        // Single link per key here, so the same-key priority rule never
        // triggers; the cost/distance/order rules below are verbatim.
        let mut best: Option<[u8; KEY_LEN]> = None;
        let mut best_cost = u64::MAX;
        let mut best_d = u64::MAX;
        for k in cands {
            let p = &self.tree.peers[&k];
            let dist = Self::coords_dist(path, &self.root_path_for(&k).unwrap_or_default());
            let cost = (p.lag.as_millis() as u64).max(1);
            let take = match best {
                None => true,
                _ if cost.saturating_mul(dist) < best_cost.saturating_mul(best_d) => true,
                _ if cost.saturating_mul(dist) > best_cost.saturating_mul(best_d) => false,
                _ if dist < best_d => true,
                _ if dist > best_d => false,
                _ if cost < best_cost => true,
                _ if cost > best_cost => false,
                _ => p.order < self.tree.peers[&best.unwrap()].order,
            };
            if take {
                best = Some(k);
                best_cost = cost;
                best_d = dist;
            }
        }
        best
    }

    /// Originate a lookup (Go `_sendLookup` + `_handleLookup` for self).
    pub(crate) async fn send_lookup(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        dest: [u8; KEY_LEN],
    ) -> Result<(), Error> {
        if let Some(e) = self.path.entries.get_mut(&dest) {
            e.req_at = Some(std::time::Instant::now());
        }
        let lookup = PathLookup {
            source: self.pubkey,
            dest,
            from: self.root_path().unwrap_or_default(),
        };
        self.handle_lookup(links, conn_peer, self.pubkey, &lookup)
            .await
    }

    /// Handle a lookup from `from` (Go `_handleLookup`): multicast onwards,
    /// then answer directly on a transformed-key match.
    pub(crate) async fn handle_lookup(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        from: [u8; KEY_LEN],
        lookup: &PathLookup,
    ) -> Result<(), Error> {
        let mut buf = Vec::new();
        lookup.encode(&mut buf);
        self.multicast(links, from, lookup.dest, FrameType::PathLookup, &buf)
            .await?;
        if crate::bloom::xkey(&lookup.dest) != crate::bloom::xkey(&self.pubkey) {
            return Ok(());
        }
        let coords = self.root_path().unwrap_or_default();
        let mut info = NotifyInfo {
            seq: crate::session::unix_now(),
            path: coords,
            sig: [0u8; 64],
        };
        if info.seq != self.path.notify.seq || info.path != self.path.notify.path {
            info.sign(&self.key);
            self.path.notify = info.clone();
        } else {
            info = self.path.notify.clone();
        }
        let notify = PathNotify {
            path: lookup.from.clone(),
            watermark: u64::MAX,
            source: self.pubkey,
            dest: lookup.source,
            info,
        };
        self.handle_notify(links, conn_peer, &notify).await
    }

    /// Handle a notify: forward toward its path, or accept it when we are
    /// the destination (Go `_handleNotify`).
    pub(crate) async fn handle_notify(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        notify: &PathNotify,
    ) -> Result<(), Error> {
        let mut fwd = notify.clone();
        if let Some(next) = self.greedy_next(&fwd.path, &mut fwd.watermark) {
            let mut buf = Vec::new();
            fwd.encode(&mut buf);
            return links.write(next, FrameType::PathNotify, &buf).await;
        }
        if notify.dest != self.pubkey {
            return Ok(());
        }
        if self.path.entries.contains_key(&notify.source) {
            let (old_seq, old_path) = {
                let e = &self.path.entries[&notify.source];
                (e.seq, e.path.clone())
            };
            if notify.info.seq <= old_seq || notify.info.path == old_path {
                return Ok(());
            }
            if !notify.check() {
                return Ok(());
            }
            if let Some(e) = self.path.entries.get_mut(&notify.source) {
                e.path = notify.info.path.clone();
                e.seq = notify.info.seq;
                e.broken = false;
                e.deadline = std::time::Instant::now() + PATH_TIMEOUT;
            }
        } else {
            if !self
                .path
                .rumors
                .contains_key(&crate::bloom::xkey(&notify.source))
            {
                return Ok(());
            }
            if !notify.check() {
                return Ok(());
            }
            self.path.entries.insert(
                notify.source,
                PathEntry {
                    path: notify.info.path.clone(),
                    seq: notify.info.seq,
                    req_at: Some(std::time::Instant::now()),
                    deadline: std::time::Instant::now() + PATH_TIMEOUT,
                    broken: false,
                },
            );
        }
        if let Some(data) = self
            .path
            .rumors
            .get_mut(&crate::bloom::xkey(&notify.source))
            .and_then(|r| r.pending.take())
        {
            let dest = notify.source;
            self.pathfinder_send(links, conn_peer, dest, data).await?;
        }
        Ok(())
    }

    /// Handle a broken-path report (Go `_handleBroken`).
    pub(crate) async fn handle_broken(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        broken: &PathBroken,
    ) -> Result<(), Error> {
        let mut fwd = broken.clone();
        if let Some(next) = self.greedy_next(&fwd.path, &mut fwd.watermark) {
            let mut buf = Vec::new();
            fwd.encode(&mut buf);
            return links.write(next, FrameType::PathBroken, &buf).await;
        }
        if broken.source != self.pubkey {
            return Ok(());
        }
        if self.path.entries.contains_key(&broken.dest) {
            if let Some(e) = self.path.entries.get_mut(&broken.dest) {
                e.broken = true;
            }
            let dest = broken.dest;
            self.rumor_lookup(links, conn_peer, dest).await?;
        }
        Ok(())
    }

    /// Throttled lookup driver (Go `_rumorSendLookup`). Rumors rendezvous
    /// by transformed key, so a notify from the full key matches a lookup
    /// for a partial key.
    pub(crate) async fn rumor_lookup(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        dest: [u8; KEY_LEN],
    ) -> Result<(), Error> {
        let now = std::time::Instant::now();
        let x = crate::bloom::xkey(&dest);
        if self
            .path
            .rumors
            .get(&x)
            .and_then(|r| r.send_at)
            .map(|t| now.duration_since(t) < PATH_THROTTLE)
            .unwrap_or(false)
        {
            return Ok(());
        }
        let e = self.path.rumors.entry(x).or_insert(RumorEntry {
            dest,
            send_at: None,
            deadline: now + PATH_TIMEOUT,
            pending: None,
        });
        e.send_at = Some(now);
        e.deadline = now + PATH_TIMEOUT;
        // Boxed: the lookup/notify/send graph is mutually recursive.
        Box::pin(self.send_lookup(links, conn_peer, dest)).await
    }

    /// Send a network-layer payload, attaching the learned path or
    /// buffering behind a lookup (Go `pathfinder._handleTraffic`).
    pub(crate) async fn pathfinder_send(
        &mut self,
        links: &mut LinkSet<'_>,
        conn_peer: [u8; KEY_LEN],
        dest: [u8; KEY_LEN],
        payload: Vec<u8>,
    ) -> Result<(), Error> {
        let path = self
            .path
            .entries
            .get(&dest)
            .filter(|e| !e.broken)
            .map(|e| e.path.clone());
        if let Some(path) = path {
            let tr = crate::traffic::Traffic {
                path,
                from: self.root_path().unwrap_or_default(),
                source: self.pubkey,
                dest,
                watermark: u64::MAX,
                payload,
            };
            return self.route_traffic(links, &tr).await;
        }
        self.rumor_lookup(links, conn_peer, dest).await?;
        if let Some(r) = self.path.rumors.get_mut(&crate::bloom::xkey(&dest)) {
            r.pending = Some(payload);
        }
        Ok(())
    }

    /// Forward locally-originated traffic one hop (Go `router.handleTraffic`
    /// for the send side; the watermark update is inside `greedy_next`).
    async fn route_traffic(
        &mut self,
        links: &mut LinkSet<'_>,
        tr: &crate::traffic::Traffic,
    ) -> Result<(), Error> {
        let mut fwd = tr.clone();
        if let Some(next) = self.greedy_next(&fwd.path, &mut fwd.watermark) {
            let buf = fwd.encode();
            return links.write(next, FrameType::Traffic, &buf).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RPUB: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
    const PPUB: &str = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394";
    const LOOKUP: &str = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3948a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c030100";
    const NOTIFY: &str = "030100ffffffffffffffffff018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394d285d8cc04040200a9b666a872fc3894af2435bf21e124680234a3df4e0db8747b7e9b99b3908d47bad956fe0400131c102b601d925aca1ed8f98739c3297ba051e8e28264537b04";
    const BROKEN: &str = "03002a8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3948a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

    fn key(s: &str) -> [u8; KEY_LEN] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn lookup_vector_matches_go() {
        let dec = PathLookup::decode_exact(&hex::decode(LOOKUP).unwrap()).unwrap();
        assert_eq!(dec.source, key(PPUB));
        assert_eq!(dec.dest, key(RPUB));
        assert_eq!(dec.from, vec![3, 1]);
        let mut out = Vec::new();
        dec.encode(&mut out);
        assert_eq!(hex::encode(out), LOOKUP);
    }

    #[test]
    fn notify_vector_matches_go() {
        let raw = hex::decode(NOTIFY).unwrap();
        let dec = PathNotify::decode_exact(&raw).unwrap();
        assert_eq!(dec.path, vec![3, 1]);
        assert_eq!(dec.watermark, u64::MAX);
        assert_eq!(dec.source, key(RPUB));
        assert_eq!(dec.dest, key(PPUB));
        assert_eq!(dec.info.seq, 1234567890);
        assert_eq!(dec.info.path, vec![4, 2]);
        assert!(dec.check());
        let mut out = Vec::new();
        dec.encode(&mut out);
        assert_eq!(hex::encode(out), NOTIFY);
    }

    #[test]
    fn broken_vector_matches_go() {
        let dec = PathBroken::decode_exact(&hex::decode(BROKEN).unwrap()).unwrap();
        assert_eq!(dec.path, vec![3]);
        assert_eq!(dec.watermark, 42);
        assert_eq!(dec.source, key(PPUB));
        assert_eq!(dec.dest, key(RPUB));
        let mut out = Vec::new();
        dec.encode(&mut out);
        assert_eq!(hex::encode(out), BROKEN);
    }

    #[test]
    fn notify_rejects_tampered_sig() {
        let mut raw = hex::decode(NOTIFY).unwrap();
        raw[20] ^= 1;
        let dec = PathNotify::decode_exact(&raw).unwrap();
        assert!(!dec.check());
    }
}
