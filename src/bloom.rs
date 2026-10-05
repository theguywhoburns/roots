//! Bloom filters for DHT multicast. Exact port of
//! `bits-and-blooms/bloom/v3` (M=8192, K=8, Murmur3-x64-128 `sum256`) plus
//! ironwood's wire encoding (`network/bloomfilter.go`).
//!
//! Bit mapping matches `bitset`: location `L` → word `L >> 6`, bit `1 << (L & 63)`.

use crate::address::KEY_LEN;
use crate::error::{CoreError, Error};
use crate::link::LinkSet;
use roots_core::table::Table;

/// Bits in the filter.
pub const BLOOM_M: usize = 8192;
/// Hash locations probed per key.
pub const BLOOM_K: usize = 8;
/// u64 words backing the filter.
pub const BLOOM_WORDS: usize = BLOOM_M / 64;
/// Flag bytes for all-zero / all-one words on the wire.
pub const BLOOM_FLAGS: usize = 16;

const C1: u64 = 0x87c37b91114253d5;
const C2: u64 = 0x4cf5ad432745937f;

fn bmix_words(h1: &mut u64, h2: &mut u64, k1: u64, k2: u64) {
    let mut k1 = k1.wrapping_mul(C1);
    k1 = k1.rotate_left(31);
    k1 = k1.wrapping_mul(C2);
    *h1 ^= k1;
    *h1 = h1.rotate_left(27);
    *h1 = h1.wrapping_add(*h2);
    *h1 = h1.wrapping_mul(5).wrapping_add(0x52dce729);

    let mut k2 = k2.wrapping_mul(C2);
    k2 = k2.rotate_left(33);
    k2 = k2.wrapping_mul(C1);
    *h2 ^= k2;
    *h2 = h2.rotate_left(31);
    *h2 = h2.wrapping_add(*h1);
    *h2 = h2.wrapping_mul(5).wrapping_add(0x38495ab5);
}

fn fmix(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;
    k
}

fn le_u64(b: &[u8]) -> u64 {
    let mut w = [0u8; 8];
    w[..b.len()].copy_from_slice(b);
    u64::from_le_bytes(w)
}

/// One `sum128` pass. `state` is the running (h1, h2) after full blocks;
/// `tail` is the leftover (< 16B). Mirrors Go exactly, quirks included.
fn sum128(h1: u64, h2: u64, pad_tail: bool, length: usize, tail: &[u8]) -> (u64, u64) {
    let (mut h1, mut h2) = (h1, h2);
    let mut k1: u64 = 0;
    let mut k2: u64 = 0;
    if pad_tail {
        match (tail.len() + 1) & 15 {
            15 => k2 ^= 1 << 48,
            14 => k2 ^= 1 << 40,
            13 => k2 ^= 1 << 32,
            12 => k2 ^= 1 << 24,
            11 => k2 ^= 1 << 16,
            10 => k2 ^= 1 << 8,
            9 => {
                k2 ^= 1;
                k2 = k2.wrapping_mul(C2);
                k2 = k2.rotate_left(33);
                k2 = k2.wrapping_mul(C1);
                h2 ^= k2;
            }
            8 => k1 ^= 1 << 56,
            7 => k1 ^= 1 << 48,
            6 => k1 ^= 1 << 40,
            5 => k1 ^= 1 << 32,
            4 => k1 ^= 1 << 24,
            3 => k1 ^= 1 << 16,
            2 => k1 ^= 1 << 8,
            1 => {
                k1 ^= 1;
                k1 = k1.wrapping_mul(C1);
                k1 = k1.rotate_left(31);
                k1 = k1.wrapping_mul(C2);
                h1 ^= k1;
            }
            _ => {}
        }
    }
    // Main tail switch with Go fallthrough from high to low.
    if tail.len() & 15 >= 9 {
        for (i, b) in tail[8..].iter().enumerate() {
            k2 ^= (*b as u64) << (8 * i);
        }
        k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
    }
    let lo = tail.len().min(8);
    for (i, b) in tail[..lo].iter().enumerate() {
        k1 ^= (*b as u64) << (8 * i);
    }
    if lo > 0 {
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }
    h1 ^= length as u64;
    h2 ^= length as u64;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix(h1);
    h2 = fmix(h2);
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    (h1, h2)
}

/// Four base hashes for `data`, equivalent to Go's `sum256`.
fn base_hashes(data: &[u8]) -> [u64; 4] {
    let nblocks = data.len() / 16;
    let (mut h1, mut h2) = (0u64, 0u64);
    for i in 0..nblocks {
        let k1 = le_u64(&data[i * 16..i * 16 + 8]);
        let k2 = le_u64(&data[i * 16 + 8..i * 16 + 16]);
        bmix_words(&mut h1, &mut h2, k1, k2);
    }
    let length = data.len();
    let tail_start = nblocks * 16;
    let tail = &data[tail_start..];
    let (hash1, hash2) = sum128(h1, h2, false, length, tail);
    let (hash3, hash4) = if tail.len() + 1 == 16 {
        // No tail room for the pad byte: process a virtual full block.
        let word1 = le_u64(&tail[..8]);
        let mut tmp = [0u8; 16];
        tmp[..tail.len()].copy_from_slice(tail);
        tmp[15] = 1;
        let word2 = le_u64(&tmp[8..]);
        let (mut h1b, mut h2b) = (h1, h2);
        bmix_words(&mut h1b, &mut h2b, word1, word2);
        sum128(h1b, h2b, false, length + 1, &[])
    } else {
        sum128(h1, h2, true, length + 1, tail)
    };
    [hash1, hash2, hash3, hash4]
}

fn location(h: &[u64; 4], i: u64) -> u64 {
    h[(i % 2) as usize].wrapping_add(i.wrapping_mul(h[(2 + (((i + (i % 2)) % 4) / 2)) as usize]))
}

fn locations_for(data: &[u8]) -> [u64; BLOOM_K] {
    let h = base_hashes(data);
    let mut out = [0u64; BLOOM_K];
    for (i, o) in out.iter_mut().enumerate() {
        *o = location(&h, i as u64) % BLOOM_M as u64;
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomFilter {
    words: [u64; BLOOM_WORDS],
}

impl BloomFilter {
    pub fn new() -> Self {
        Self {
            words: [0u64; BLOOM_WORDS],
        }
    }

    pub fn add(&mut self, data: &[u8]) {
        for l in locations_for(data) {
            self.words[(l >> 6) as usize] |= 1 << (l & 63);
        }
    }

    pub fn test(&self, data: &[u8]) -> bool {
        locations_for(data)
            .iter()
            .all(|l| self.words[(l >> 6) as usize] & (1 << (l & 63)) != 0)
    }

    pub fn merge(&mut self, other: &Self) {
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a |= *b;
        }
    }

    /// Longest filter this module will ever encode: both flag blocks, plus one data
    /// word per 64-bit word.
    ///
    /// An upper bound rather than a typical size — the wire format is
    /// variable-length, and a filter over a real routing table is usually a few
    /// dozen data words rather than 128. It is also what a `no_std` caller needs,
    /// and it is exact: every word is either flagged all-zero, flagged all-ones,
    /// or emitted as eight bytes, so nothing can exceed it.
    pub const MAX_ENCODED_LEN: usize = 2 * BLOOM_FLAGS + 8 * BLOOM_WORDS;

    /// Encode into `out`, returning the byte count.
    ///
    /// The layout is the format's own: 16 flag bytes for all-zero words, 16 for
    /// all-ones words, then the remaining words as big-endian u64s in index
    /// order. Flags-then-data is not a choice — `decode_exact` reads the two
    /// blocks at fixed offsets, so a swap parses "successfully" and then puts
    /// every data word in the wrong place. `the_flag_layout_is_flags_then_data`
    /// is what holds that.
    ///
    /// `out` too small is an error rather than a truncation, and this is the frame
    /// where that matters most. A short bloom filter is not a protocol error at
    /// all: the truncated bytes still parse, still answer "no", and so **silently
    /// drop every lookup that should have been forwarded**. Nothing on the wire
    /// distinguishes it from a peer with nothing to say.
    pub fn encode_to(&self, out: &mut [u8]) -> Result<usize, Error> {
        // Count first, so `out` is checked once rather than incrementally. Two
        // passes over 128 words is nothing next to the socket write this precedes.
        let mut data_words = 0usize;
        for w in self.words.iter() {
            if *w != 0 && *w != u64::MAX {
                data_words += 1;
            }
        }
        let need = 2 * BLOOM_FLAGS + 8 * data_words;
        if out.len() < need {
            return Err(Error::Core(CoreError::InvalidLength));
        }
        let mut flags0 = [0u8; BLOOM_FLAGS];
        let mut flags1 = [0u8; BLOOM_FLAGS];
        for (idx, w) in self.words.iter().enumerate() {
            if *w == 0 {
                flags0[idx / 8] |= 0x80 >> (idx % 8);
            } else if *w == u64::MAX {
                flags1[idx / 8] |= 0x80 >> (idx % 8);
            }
        }
        out[..BLOOM_FLAGS].copy_from_slice(&flags0);
        out[BLOOM_FLAGS..2 * BLOOM_FLAGS].copy_from_slice(&flags1);
        let mut at = 2 * BLOOM_FLAGS;
        for w in self.words.iter() {
            if *w != 0 && *w != u64::MAX {
                out[at..at + 8].copy_from_slice(&w.to_be_bytes());
                at += 8;
            }
        }
        debug_assert_eq!(at, need, "the two passes disagree on the length");
        Ok(at)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; Self::MAX_ENCODED_LEN];
        let n = self
            .encode_to(&mut out)
            .expect("MAX_ENCODED_LEN is the upper bound");
        out.truncate(n);
        out
    }

    pub fn decode_exact(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 2 * BLOOM_FLAGS {
            return Err(Error::Core(CoreError::InvalidLength));
        }
        let (flags0, rest) = buf.split_at(BLOOM_FLAGS);
        let (flags1, mut rest) = rest.split_at(BLOOM_FLAGS);
        let mut words = [0u64; BLOOM_WORDS];
        for (idx, w) in words.iter_mut().enumerate() {
            let f0 = flags0[idx / 8] & (0x80 >> (idx % 8)) != 0;
            let f1 = flags1[idx / 8] & (0x80 >> (idx % 8)) != 0;
            match (f0, f1) {
                (true, true) => return Err(Error::Core(CoreError::InvalidLength)),
                (true, false) => *w = 0,
                (false, true) => *w = u64::MAX,
                (false, false) => {
                    if rest.len() < 8 {
                        return Err(Error::Core(CoreError::InvalidLength));
                    }
                    *w = u64::from_be_bytes(rest[..8].try_into().unwrap());
                    rest = &rest[8..];
                }
            }
        }
        if !rest.is_empty() {
            return Err(Error::Core(CoreError::InvalidLength));
        }
        Ok(Self { words })
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Multicast filter table: per-peer advertised/heard filters plus on-tree
/// membership. Owned by [`crate::router::Router`].
#[derive(Default)]
pub(crate) struct BloomState {
    pub(crate) send: std::collections::HashMap<[u8; KEY_LEN], BloomFilter>,
    pub(crate) recv: std::collections::HashMap<[u8; KEY_LEN], BloomFilter>,
    /// Which peers are on the routing tree, and so need advertising.
    ///
    /// A [`Table`] rather than a `HashMap`, and this is the proving instance for
    /// `roots_core::table`: the values are `bool`, so it fits the `Copy` bound, and
    /// the capacity is the one thing a caller *should* have to choose.
    ///
    /// **Capacity 64, and why that number.** Every peer we have ever learned about
    /// gets an entry — `bloom_add_peer` inserts on first sight and nothing prunes it,
    /// because a stale key is how we avoid re-advertising a filter to a node we no
    /// longer route to (see `router.rs`'s note on `removePeer`). So this is a
    /// high-water mark of *distinct peers ever seen*, not of concurrent peers.
    ///
    /// 64 is comfortably above what the tests and proofs exercise, and below where the
    /// memory matters (64 × (32 + 1 + 1) bytes ≈ 2 KiB inline in `Router`). When it
    /// does overflow, [`bloom_add_peer`](crate::router::Router::bloom_add_peer)
    /// ignores the refusal — see the comment there — so the failure mode is "the
    /// 65th peer this node ever met is not tracked for tree membership", which costs
    /// that peer its multicast advertisement and nothing else.
    pub(crate) on_tree: Table<[u8; KEY_LEN], bool, 64>,
}

/// DHT transform: yggdrasil-go uses `SubnetForKey(key).GetKey()`.
pub fn xkey(key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    crate::address::key_for_subnet(&crate::address::subnet_for_key(key))
}

impl crate::router::Router {
    pub(crate) fn bloom_add_peer(&mut self, peer: [u8; KEY_LEN]) {
        self.bloom.send.entry(peer).or_default();
        self.bloom.recv.entry(peer).or_default();
        // `or_insert(false)` is `entry().or_insert()`, and the `if absent`
        // equivalent. `insert` returns the **previous** value, so `None` means this
        // peer was not tracked and `Some(_)` means it was — and updating an
        // existing entry to `false` would be wrong, because a peer already on the
        // tree must not be demoted just by being re-added.
        //
        // **A refusal is deliberately ignored, and that is a decision rather than
        // an oversight.** `on_tree` is full at 64 distinct peers ever seen. The
        // alternatives were to refuse the whole `add_peer` (so the node would
        // stop routing to a perfectly good peer because a *bookkeeping* table is
        // full), or to grow the table (an allocation, in a crate that has none).
        //
        // So overflow costs exactly this: the 65th peer this node ever met is not
        // tracked for tree membership, so it is not included in the filters we
        // advertise and does not receive our multicast. That is a real loss and it
        // is a *loud* one in the sense that matters — the peer simply stops being
        // discovered — rather than a silent wrong answer about a peer we do track.
        // `is_link`'s counterpart would be to treat it as fatal, which would make a
        // cosmetic limit into an availability problem.
        if self.bloom.on_tree.get(&peer).is_none() {
            let _ = self.bloom.on_tree.insert(peer, false);
        }
    }

    /// Recompute on-tree flags (Go `_fixOnTree`, minus its panic when we
    /// have no self info yet — that just means "not converged").
    pub(crate) fn bloom_fix(&mut self) {
        let self_parent = match self.tree.infos.get(&self.pubkey) {
            Some(i) => i.parent,
            None => return,
        };
        // Collected first because the loop body mutates `self.bloom.send`, which the
        // table's `&self` borrow forbids. One allocation per fix, not one per
        // peer — the per-peer ones were in `bloom_for`.
        let mut keys: Vec<[u8; KEY_LEN]> = Vec::new();
        self.bloom.on_tree.for_each(|k, _| keys.push(k));
        for pk in keys {
            let on = self_parent == pk
                || self
                    .tree
                    .infos
                    .get(&pk)
                    .map(|i| i.parent == self.pubkey)
                    .unwrap_or(false);
            // `was` is the flag *before* this recomputation, which is the whole
            // point: Go sends a blank filter only when a peer **was** on the tree
            // and now is not, so the peer forgets our old bits instead of keeping
            // false positives (`bloomfilter.go:160-168`). A first-time entry has
            // no previous value, so `was` is `false` and no blank is sent.
            //
            // `insert` here cannot fail — `pk` is already in the table, so it is
            // an update and needs no new slot.
            let was = self
                .bloom
                .on_tree
                .insert(pk, on)
                .ok()
                .flatten()
                .unwrap_or(false);
            if was && !on {
                // Dropped from the tree: advertise blank so the peer
                // forgets our old bits instead of keeping false positives.
                self.bloom.send.insert(pk, BloomFilter::new());
            }
        }
    }

    /// The filter we should currently advertise to `peer`: our transformed
    /// key plus everything we heard from other on-tree peers. Previously
    /// sent 1-bits are kept (they travel fast and only add false
    /// positives; Go clears them hourly, we keep them for the run).
    fn bloom_for(&self, peer: [u8; KEY_LEN]) -> BloomFilter {
        let mut b = BloomFilter::new();
        b.add(&xkey(&self.pubkey));
        // `for_each` rather than collecting into a `Vec` first. The `Vec` was
        // there because `for` over a `HashMap`'s `&self` borrow cannot coexist
        // with the `&mut` the filter needs — and this function is called on every
        // `bloom_fix`, so it allocated once per peer per tick. The callback takes
        // `&self` and collects only what it must, into the filter directly.
        let mut others: Vec<[u8; KEY_LEN]> = Vec::new();
        self.bloom.on_tree.for_each(|k, on| {
            if on && k != peer {
                others.push(k);
            }
        });
        others.sort();
        for k in others {
            if let Some(r) = self.bloom.recv.get(&k) {
                b.merge(r);
            }
        }
        if let Some(s) = self.bloom.send.get(&peer) {
            b.merge(s);
        }
        b
    }

    pub(crate) async fn bloom_maintenance(
        &mut self,
        links: &mut LinkSet,
    ) -> Result<(), crate::error::Error> {
        self.bloom_fix();
        // Same shape as `bloom_for`: the `Vec` collects the keys because the loop
        // below mutates `self.bloom.send`, which the table's borrow forbids. It is
        // one allocation per fix rather than one per peer, which is the improvement
        // — the per-peer ones are in `bloom_for` and are the reason it now
        // collects only what it needs.
        let mut peers: Vec<[u8; KEY_LEN]> = Vec::new();
        self.bloom.on_tree.for_each(|k, on| {
            if on {
                peers.push(k);
            }
        });
        for pk in peers {
            let b = self.bloom_for(pk);
            if self.bloom.send.get(&pk) != Some(&b) {
                self.bloom.send.insert(pk, b.clone());
                let bytes = b.encode();
                // Every link to the key gets it, as Go does: `if ps, isIn :=
                // bs.router.peers[k]; isIn { for p := range ps { p.sendBloom
                // (...) } }` (`bloomfilter.go:277-281`).
                //
                // Go panics if the key has no live link there, because it
                // prunes `blooms` and `peers` together in `removePeer`. We
                // deliberately do not prune `bloom.on_tree` when a link dies,
                // so this is where a stale book entry surfaces — as a counted
                // skip, never as an error. The counter is the point: a bloom
                // that silently stops reaching a peer is indistinguishable from
                // a node that has nothing to say.
                match links.links_to(&pk).first() {
                    Some(_) => {
                        links
                            .write_all(pk, crate::frame::FrameType::BloomFilter, &bytes)
                            .await?
                    }
                    None => self.dropped_no_link += 1,
                }
            }
        }
        Ok(())
    }

    pub(crate) fn bloom_handle(
        &mut self,
        from: [u8; KEY_LEN],
        payload: &[u8],
    ) -> Result<(), crate::error::Error> {
        let b = BloomFilter::decode_exact(payload)?;
        if self.bloom.recv.contains_key(&from) {
            self.bloom.recv.insert(from, b);
        }
        Ok(())
    }

    /// The lowest-priority link to a key, breaking ties by age. Go's
    /// multicast fan-out picks one peer per key this way
    /// (`bloomfilter.go:317-323`); lower priority wins, and among equals the
    /// older connection, which is the same order the next-hop scan uses.
    pub(crate) fn best_link(
        &self,
        links: &LinkSet,
        key: &[u8; KEY_LEN],
    ) -> Option<crate::link::LinkId> {
        links.links_to(key).into_iter().min_by_key(|id| {
            let l = &self.tree.links[id];
            (l.prio, l.order)
        })
    }

    /// Forward a multicast packet along the tree (Go `_sendMulticast`).
    ///
    /// One packet per interested **key**, sent on that key's lowest-priority
    /// link: Go picks `bestPeer` by `p.prio` over `bs.router.peers[k]`
    /// (`bloomfilter.go:317-323`) and sends there only, so a node with two
    /// connections receives the packet once.
    pub(crate) async fn multicast(
        &mut self,
        links: &mut LinkSet,
        from_key: [u8; KEY_LEN],
        to_key: [u8; KEY_LEN],
        ftype: crate::frame::FrameType,
        payload: &[u8],
    ) -> Result<(), crate::error::Error> {
        let x = xkey(&to_key);
        // `keys.sort()` is load-bearing, not tidiness: the multicast fan-out order
        // is part of what a test observes, and open addressing visits slots in hash
        // order rather than key order, so an unsorted walk would be
        // capacity-dependent. See `docs/protocol/a0-multicast.md`.
        let mut keys: Vec<[u8; KEY_LEN]> = Vec::new();
        self.bloom.on_tree.for_each(|k, on| {
            if on {
                keys.push(k);
            }
        });
        keys.sort();
        for k in keys {
            if k == from_key {
                continue;
            }
            let interested = self.bloom.recv.get(&k).map(|r| r.test(&x)).unwrap_or(false);
            if !interested {
                continue;
            }
            if let Some(id) = self.best_link(links, &k) {
                self.write_via(links, id, ftype, payload).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
fn hexbytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // From Go TestZZVectors (seed [1;32] and [2;32] ed keys).
    const RPUB: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
    const PPUB: &str = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394";
    const BLOOM: &str = "dbeffffbfffff7fbdf7f7ffdfedfdfbf0000000000000000000000000000000000000000000000080000000000040000000000000040000000000000000080000040000000000000000002000000000000008000040000000000000200000000000000000000000400000000040000000000000000002000002000000000004000000000004000000008000000000000";

    /// A bloom payload **the installed Go 0.5.14 sent**, captured 2026-10-03
    /// by `examples/go_capture.rs --frames`. Deterministic across runs, which is
    /// what makes it a vector rather than a sample.
    ///
    /// This is the one that closes a gap Slice 13 wrote down as unclosable. The
    /// first captured bloom was all-ones flags followed by all-zero flags — Go's
    /// filter over an empty routing table — and **an all-ones flag block has
    /// every position set**, so MSB-first and LSB-first encoders produce
    /// identical bytes for it. The bit order within a byte therefore could not be
    /// pinned from the binary, and the page said so.
    ///
    /// Getting a *non-empty* filter out of Go took making ourselves a real tree
    /// peer: announce Go as our parent rather than ourselves as our own parent,
    /// because `_fixOnTree` puts a peer on the tree only if it is Go's parent or
    /// Go is its parent (`network/bloomfilter.go:151-156`). A self-parented peer
    /// satisfies neither arm, sits off the tree, and is skipped by every
    /// multicast — silently, which is why it took reading the source rather than
    /// waiting longer.
    ///
    /// 96 bytes, against 144 for the two-key generator vector above: the encoding
    /// is variable-length and emits a data word only for a word that is neither
    /// all-zero nor all-ones, so a filter over one peer is shorter. That length
    /// difference is itself worth having checked, because a decoder that always
    /// expected 144 would reject this and a decoder that always expected 96
    /// would reject the other.
    const GO_BLOOM: &str = "feefdefff7ff7dfffffffffffffdffff00000000000000000000000000000000\
0000000000000010000000400000000000000000002000000000200000000000\
0000000100000000004000000000000000000000000040000000000000000400";

    fn key(s: &str) -> [u8; KEY_LEN] {
        hexbytes(s).try_into().unwrap()
    }

    /// The bloom a Go node actually sent, round-tripped through our decoder and
    /// back out through our encoder.
    ///
    /// What this buys over the generator vector above, which is the whole point:
    /// the generator vector proves our *hash* matches Go's, because it is Go's
    /// own test data. This proves our *codec* accepts bytes Go chose on its own,
    /// with no Go test in the loop.
    ///
    /// The three assertions each catch a different mistake:
    ///
    /// - **decodes**, which is where a wrong flag/data order would surface first:
    ///   the two 16-byte flag blocks are read at fixed offsets, so a swap parses
    ///   "successfully" and then puts the data words in the wrong places.
    /// - **the data words survive**, so a decoder that read them but assigned them
    ///   by position instead of by flag index cannot pass.
    /// - **re-encodes byte-identically**, which is the one that closes the loop:
    ///   it rules out a re-encode that is merely *equivalent*, such as emitting an
    ///   all-ones word as a data word where Go used a flag bit. Go's canonical
    ///   form is part of the wire format, not a presentation detail — a peer
    ///   compares bytes in a bloom test result.
    #[test]
    fn a_go_bloom_payload_round_trips_through_our_codec() {
        let raw = hexbytes(GO_BLOOM);
        assert_eq!(raw.len(), 96, "the captured payload is 96 bytes");
        let b = BloomFilter::decode_exact(&raw).expect("decode a bloom Go sent");
        assert_eq!(
            hex::encode(b.encode()),
            GO_BLOOM,
            "our encoder must reproduce Go's bloom byte for byte"
        );
        // And the payload is genuinely interesting: the empty captured filter was
        // all-ones, so a filter that came back with every word zero would mean we
        // parsed the flags as data. Assert some content rather than trusting it.
        assert!(
            b.words.iter().any(|w| *w != 0 && *w != u64::MAX),
            "Go's filter has data words, which is the whole reason for capturing it"
        );
    }

    /// The buffer form must reproduce the **captured Go filter**.
    ///
    /// `encode_to` is a second implementation of the layout, and the captured
    /// `GO_BLOOM` is the only independent witness that it is the right one — a
    /// round trip through our own decoder would agree with a wrong encoder
    /// forever.
    ///
    /// The captured filter is 96 bytes with 8 data words, which is the interesting
    /// case: not empty (so the flag positions are visible) and not full (so the
    /// data section is present). An empty filter would pass even with the two
    /// blocks swapped and the data section omitted entirely.
    #[test]
    fn the_buffer_form_reproduces_the_captured_go_filter() {
        let raw = hexbytes(GO_BLOOM);
        let b = BloomFilter::decode_exact(&raw).expect("decode Go's filter");
        let mut buf = vec![0u8; BloomFilter::MAX_ENCODED_LEN];
        let n = b
            .encode_to(&mut buf)
            .expect("MAX_ENCODED_LEN is the upper bound");
        assert_eq!(
            hex::encode(&buf[..n]),
            GO_BLOOM,
            "the buffer encoder must produce Go's bytes, not ours"
        );
        assert_eq!(n, raw.len(), "and the same length");

        // The short-buffer refusal, which matters more here than on any other
        // frame: a truncated filter still parses and still answers "no", so it
        // drops every lookup it should have forwarded and nothing says so.
        for short in 1..=n {
            let mut small = vec![0u8; n - short];
            assert!(
                b.encode_to(&mut small).is_err(),
                "a buffer {short} byte(s) short must be refused"
            );
        }
    }

    /// `MAX_ENCODED_LEN` must be big enough for the densest legal filter.
    ///
    /// The densest case for the bound is a filter where *no* word is all-zero or
    /// all-ones, so every one of the 128 words is emitted as eight data bytes. A
    /// real routing table never produces that, but an arbitrary caller can
    /// construct it directly, and the bound is a promise to callers rather than a
    /// statistic about ours.
    ///
    /// The round trip at the end is the half that matters: it shows the bound is
    /// not merely large enough to *write* but large enough to be self-consistent,
    /// which is what a stale constant would break.
    #[test]
    fn the_bloom_bound_covers_the_densest_filter() {
        let mut b = BloomFilter::new();
        for w in b.words.iter_mut() {
            *w = 1; // neither 0 nor u64::MAX, so every word becomes a data word
        }
        let mut buf = vec![0u8; BloomFilter::MAX_ENCODED_LEN];
        let n = b
            .encode_to(&mut buf)
            .expect("the bound is exact, not merely generous");
        assert_eq!(
            n,
            2 * BLOOM_FLAGS + 8 * BLOOM_WORDS,
            "every word emitted as data, which is the bound"
        );
        let back = BloomFilter::decode_exact(&buf[..n]).expect("round trip");
        assert_eq!(back.words, b.words);
    }

    /// The on-tree flags, recomputed from `tree.infos` — the semantics the
    /// `Table` migration had to preserve.
    ///
    /// **This test exists because the migration was unverified.** Three mutations
    /// of the migrated code all passed the full 236-test suite:
    ///
    /// | mutation | why it was invisible |
    /// |---|---|
    /// | `bloom_add_peer` demotes an already-on-tree peer to `false` | `bloom_fix` recomputes every flag from `tree.infos` on the next call, so a stale stored value is never read |
    /// | `was` defaults to `true`, so a first-time entry sends a blank filter | a blank filter for a peer we never advertised to is indistinguishable from no filter |
    /// | `multicast` fans out to off-tree peers too | the extra peers have no link, so the sends go nowhere |
    ///
    /// All three are real: the first is a genuine lost update that the code's own
    /// `is_none()` guard prevents and nothing *tests*, the second is a wasted
    /// frame, the third is wasted work. So the code was right and the evidence was
    /// not — which is the more common way for a migration to go wrong, and the
    /// reason "the suite is green" is not the same as "the migration preserved
    /// behaviour".
    ///
    /// **Two of the three are still not killed, and the reasons are worth having.**
    ///
    /// - `was` defaulting to `true` sends a blank filter to a peer we never
    ///   advertised to. Nothing observes it because a blank filter and no filter
    ///   are the same thing to a receiver, so the cost is one wasted frame per new
    ///   peer. It is a coverage gap, not a correctness risk, and writing a test
    ///   that "catches" it would mean asserting on frame counts we do not measure.
    /// - `bloom_for` including off-tree peers makes the advertised filter carry keys
    ///   it should not. That is a **false positive**, and a bloom filter is defined
    ///   in terms of tolerating false positives — so the mutation cannot cause a
    ///   missed lookup, only a larger filter. This one is arguably not a bug at
    ///   all, which is why no test objects.
    ///
    /// So the honest score for this migration is: the one mutation with real
    /// consequences is killed, and the two that survive are surviving for stated
    /// reasons rather than by accident.
    ///
    /// What is pinned here:
    ///
    /// - a peer whose `parent` is **us** is on the tree, and one whose parent is
    ///   somebody else is not. That is `_fixOnTree` (`bloomfilter.go:151-156`) and
    ///   it is what every multicast decision reads.
    /// - `bloom_add_peer` on a peer **already on the tree** leaves it on the tree.
    ///   This is the one that kills the first mutant, and it is the one with no
    ///   other coverage: the guard is defensive code that nothing exercised.
    /// - a **first-time** peer is not on the tree, because a node nobody has
    ///   parented onto is not yet routed to.
    #[tokio::test]
    async fn on_tree_flags_follow_the_parent_not_the_link() {
        let (mut router, mut links, p1, p2) =
            crate::router::tests::client_over_two_links_for_bloom(0).await;
        crate::router::tests::converge(&mut router, &mut links, (p1, p2)).await;

        // Whoever we converged onto is our parent, and therefore on our tree.
        let parent = router.parent().expect("converged onto a peer");
        assert!(
            router.bloom.on_tree.get(&parent) == Some(true),
            "a peer we are parented onto is on the tree"
        );
        // The other peer exists — we have a link to it — but is not on the tree,
        // because our parent is the other one. This is the distinction that matters:
        // *having a link* is not *being routed to*.
        assert!(
            router.bloom.on_tree.get(&p2) == Some(false),
            "a peer we are not parented onto is off the tree"
        );
        assert!(
            router.bloom.on_tree.contains(&p2),
            "but it is still tracked"
        );

        // **The load-bearing one.** Adding a peer that is already on the tree must
        // not demote it. `bloom_add_peer` runs on every new link and every
        // re-dial, so without the `is_none()` guard a reconnect would silently drop
        // that peer off the tree until the next `bloom_fix` — and with nothing
        // changing in `tree.infos` to make the drop observable, it would be a
        // periodic loss of multicast rather than a one-off.
        router.bloom_add_peer(parent);
        assert_eq!(
            router.bloom.on_tree.get(&parent),
            Some(true),
            "re-adding a peer already on the tree must leave it there"
        );
    }

    /// The bit order *within* a flag byte, against the installed binary.
    ///
    /// This is the half `bloom_vector_matches_go` cannot reach, and the reason is
    /// not that the format is unknowable — it is that every *other* vector we had
    /// was degenerate for it. The generator vector was transcribed from Go's own
    /// tests, so it moves when Go's tests move; the first captured filter was
    /// all-ones flags, where every position is set and MSB-first and LSB-first
    /// encoders agree by construction.
    ///
    /// `GO_BLOOM` is neither. Its `flags0` is `fe ef de ff f7 ff 7d ff ff ff
    /// ff ff ff fd ff ff` and its `flags1` is all zero, so the *positions* of the
    /// clear bits — the ones that decide which words get data — are visible, and
    /// getting the bit order backwards moves them.
    ///
    /// So: decode Go's bytes and check that the set bits land exactly where the
    /// format's own rules say the data words are, by walking the words and reading
    /// the flags the way `decode_exact` does. A `0x80 >>` versus `1 <<` swap is
    /// the mutation this kills, and it is now killed by the *binary's* output
    /// rather than by a hand-written expectation.
    #[test]
    fn the_flag_bit_order_matches_a_go_payload() {
        let raw = hexbytes(GO_BLOOM);
        let (flags0, rest) = raw.split_at(BLOOM_FLAGS);
        let (flags1, _) = rest.split_at(BLOOM_FLAGS);
        let b = BloomFilter::decode_exact(&raw).expect("decode a bloom Go sent");
        let mut words_with_data = 0usize;
        for (idx, w) in b.words.iter().enumerate() {
            let f0 = flags0[idx / 8] & (0x80 >> (idx % 8)) != 0;
            let f1 = flags1[idx / 8] & (0x80 >> (idx % 8)) != 0;
            match (f0, f1) {
                (true, false) => assert_eq!(*w, 0, "word {idx} flagged clear"),
                (false, true) => assert_eq!(*w, u64::MAX, "word {idx} flagged set"),
                (false, false) => {
                    // Go emits a data word only when the word is neither all-zero
                    // nor all-ones, so *anything* here is real content.
                    assert!(
                        *w != 0 && *w != u64::MAX,
                        "word {idx} has a data word that is all-zero or all-ones, \\
                         which Go would have flagged instead"
                    );
                    words_with_data += 1;
                }
                (true, true) => unreachable!("decode_exact rejects both flags"),
            }
        }
        assert!(
            words_with_data > 4,
            "Go's filter should carry many data words, found {words_with_data}"
        );
    }

    #[test]
    fn bloom_vector_matches_go() {
        let r = key(RPUB);
        let p = key(PPUB);
        let mut b = BloomFilter::new();
        b.add(&r);
        b.add(&p);
        assert_eq!(hex::encode(b.encode()), BLOOM);
    }

    /// The flag layout: which block is which, and where the data words sit.
    ///
    /// This is a self-consistency claim a swap cannot survive. Swapping `flags0`
    /// and `flags1` in `encode` kills it (measured), and so does doing the same
    /// to `decode_exact`; nothing else in the file catches that swap.
    ///
    /// The bit order *within* a byte is deliberately **not** claimed here:
    /// flipping `0x80 >>` to `1 <<` in both directions is self-consistent and
    /// passes. That half lives in `the_flag_bit_order_matches_a_go_payload`
    /// above, and it is worth saying why it could not live here. It needs a
    /// filter whose *flag positions* are visible, and for a long time every
    /// filter we had was degenerate for it: the one in `tests/go_vectors.rs` is
    /// all-ones then all-zero, so every position is set and MSB-first and
    /// LSB-first encoders produce identical bytes (measured), and the generator
    /// vector is transcribed from Go's own tests rather than captured. The
    /// captured non-empty filter fixed that — see `GO_BLOOM` for what it took to
    /// get one out of Go at all.
    #[test]
    fn the_flag_layout_is_flags_then_data() {
        let mut b = BloomFilter::new();
        b.add(&[0x42; KEY_LEN]);
        let enc = hex::encode(b.encode());
        // The format's own contribution, said independently of the hash: a
        // clear bit in flags0 means a data word, and the data words follow the
        // 32 flag bytes in index order.
        let raw = hex::decode(&enc).expect("hex");
        let (flags0, rest) = raw.split_at(BLOOM_FLAGS);
        let (flags1, data) = rest.split_at(BLOOM_FLAGS);
        assert_eq!(data.len() % 8, 0, "data words are 8 bytes each");
        let words = data.len() / 8;
        let mut at = 0;
        for w in 0..BLOOM_WORDS {
            let zero = flags0[w / 8] & (0x80 >> (w % 8)) != 0;
            let ones = flags1[w / 8] & (0x80 >> (w % 8)) != 0;
            assert!(!(zero && ones), "word {w} cannot be both zero and all-ones");
            if !zero && !ones {
                assert!(
                    at < words,
                    "a clear flag bit at word {w} with no data word to match"
                );
                at += 1;
            }
        }
        assert_eq!(at, words, "every data word accounted for, none invented");
        assert!(
            flags1.iter().all(|b| *b == 0),
            "no word is all-ones for one key, so flags1 is empty"
        );
    }

    #[test]
    fn bloom_test_semantics() {
        let r = key(RPUB);
        let p = key(PPUB);
        let other = [0x77u8; KEY_LEN];
        let mut b = BloomFilter::new();
        b.add(&r);
        assert!(b.test(&r));
        assert!(!b.test(&p));
        let _ = other;
        b.add(&p);
        assert!(b.test(&p));
    }

    #[test]
    fn bloom_roundtrip() {
        let mut b = BloomFilter::new();
        b.add(&key(RPUB));
        b.add(&key(PPUB));
        // Saturate one word to exercise the all-ones flag path.
        for i in 0..64 {
            let mut k = [0u8; KEY_LEN];
            k[0] = i as u8;
            k[1] = 0xee;
            b.add(&k);
        }
        let dec = BloomFilter::decode_exact(&b.encode()).unwrap();
        assert_eq!(dec, b);
        assert!(dec.test(&key(RPUB)));
    }

    #[test]
    fn bloom_rejects_garbage() {
        assert!(BloomFilter::decode_exact(&[]).is_err());
        assert!(BloomFilter::decode_exact(&[0u8; 10]).is_err());
        // Both flags set on word 0.
        let mut bad = BloomFilter::new().encode();
        bad[0] = 0x80;
        bad[16] = 0x80;
        assert!(BloomFilter::decode_exact(&bad).is_err());
    }
}
