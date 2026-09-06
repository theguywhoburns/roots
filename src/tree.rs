//! Spanning-tree protocol: `SigReq`/`SigRes`/`Announce` wire types plus
//! the deterministic parent-selection / announce rules. Port of
//! `ironwood/network/router.go` (one `impl Router` extension among several:
//! `bloom`, `pathfind`, `session`, `traffic`, `proto`); orchestration
//! (`register`, `serve`, `resolve`, …) lives in `src/router.rs`.
//!
//! Wire encodings (all integers are LEB128 uvarints):
//! - `SigReq`: `seq + nonce`
//! - `SigRes`: `SigReq + port + psig[64]`, where
//!   `psig = Sign(parent, node || parent || seq || nonce || port)`
//! - `Announce`: `key[32] + parent[32] + SigRes + sig[64]`, where
//!   `sig = Sign(key, key || parent || seq || nonce || port)`

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::address::KEY_LEN;
use crate::error::Error;
use crate::frame::{FrameType, append_uvarint, read_uvarint};
use crate::link::LinkSet;
use crate::router::UNKNOWN_LATENCY;

/// Self-announce refresh (Go: `routerRefresh` 4min).
pub const TREE_REFRESH: Duration = Duration::from_secs(4 * 60);
/// Expiry for other nodes' infos (Go: `routerTimeout` 5min).
pub const TREE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

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
    pub(crate) fn announce(&self, key: [u8; KEY_LEN]) -> Announce {
        Announce {
            key,
            parent: self.parent,
            res: self.res,
            sig: self.sig,
        }
    }
}

impl crate::router::Router {
    pub(crate) fn new_req(&self) -> SigReq {
        SigReq {
            seq: self
                .infos
                .get(&self.pubkey)
                .map(|i| i.res.req.seq + 1)
                .unwrap_or(1),
            nonce: rand::random(),
        }
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
    pub(crate) async fn handle_request(
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
    pub(crate) fn handle_response(&mut self, peer_key: [u8; KEY_LEN], res: SigRes) {
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
            TREE_REFRESH
        } else {
            TREE_TIMEOUT
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
    pub(crate) fn expire(&mut self) {
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
            self.self_refresh_at = Some(now + TREE_REFRESH);
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
    pub(crate) async fn fix(
        &mut self,
        links: &mut LinkSet<'_>,
        peer_key: [u8; KEY_LEN],
    ) -> Result<(), Error> {
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
        self.self_refresh_at = Some(Instant::now() + TREE_REFRESH);
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
    pub(crate) async fn send_announces(
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
    pub(crate) fn handle_announce(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::Router;

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
}
