//! Bloom filters for DHT multicast. Exact port of
//! `bits-and-blooms/bloom/v3` (M=8192, K=8, Murmur3-x64-128 `sum256`) plus
//! ironwood's wire encoding (`network/bloomfilter.go`).
//!
//! Bit mapping matches `bitset`: location `L` → word `L >> 6`, bit `1 << (L & 63)`.

use crate::address::KEY_LEN;
use crate::error::Error;
use crate::link::{PeerConn, Transport};

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

    pub fn encode(&self) -> Vec<u8> {
        let mut flags0 = [0u8; BLOOM_FLAGS];
        let mut flags1 = [0u8; BLOOM_FLAGS];
        let mut keep = Vec::new();
        for (idx, w) in self.words.iter().enumerate() {
            if *w == 0 {
                flags0[idx / 8] |= 0x80 >> (idx % 8);
            } else if *w == u64::MAX {
                flags1[idx / 8] |= 0x80 >> (idx % 8);
            } else {
                keep.push(*w);
            }
        }
        let mut out = Vec::with_capacity(2 * BLOOM_FLAGS + 8 * keep.len());
        out.extend_from_slice(&flags0);
        out.extend_from_slice(&flags1);
        for w in keep {
            out.extend_from_slice(&w.to_be_bytes());
        }
        out
    }

    pub fn decode_exact(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 2 * BLOOM_FLAGS {
            return Err(Error::InvalidLength);
        }
        let (flags0, rest) = buf.split_at(BLOOM_FLAGS);
        let (flags1, mut rest) = rest.split_at(BLOOM_FLAGS);
        let mut words = [0u64; BLOOM_WORDS];
        for (idx, w) in words.iter_mut().enumerate() {
            let f0 = flags0[idx / 8] & (0x80 >> (idx % 8)) != 0;
            let f1 = flags1[idx / 8] & (0x80 >> (idx % 8)) != 0;
            match (f0, f1) {
                (true, true) => return Err(Error::InvalidLength),
                (true, false) => *w = 0,
                (false, true) => *w = u64::MAX,
                (false, false) => {
                    if rest.len() < 8 {
                        return Err(Error::InvalidLength);
                    }
                    *w = u64::from_be_bytes(rest[..8].try_into().unwrap());
                    rest = &rest[8..];
                }
            }
        }
        if !rest.is_empty() {
            return Err(Error::InvalidLength);
        }
        Ok(Self { words })
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// DHT transform: yggdrasil-go uses `SubnetForKey(key).GetKey()`.
pub fn xkey(key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    crate::address::key_for_subnet(&crate::address::subnet_for_key(key))
}

impl crate::router::Router {
    pub(crate) fn bloom_add_peer(&mut self, peer: [u8; KEY_LEN]) {
        self.bloom_send.entry(peer).or_default();
        self.bloom_recv.entry(peer).or_default();
        self.bloom_on_tree.entry(peer).or_insert(false);
        self.bloom_dirty.entry(peer).or_insert(false);
    }

    /// Recompute on-tree flags (Go `_fixOnTree`, minus its panic when we
    /// have no self info yet — that just means "not converged").
    pub(crate) fn bloom_fix(&mut self) {
        let self_parent = match self.infos.get(&self.pubkey) {
            Some(i) => i.parent,
            None => return,
        };
        let keys: Vec<[u8; KEY_LEN]> = self.bloom_on_tree.keys().copied().collect();
        for pk in keys {
            let on = self_parent == pk
                || self
                    .infos
                    .get(&pk)
                    .map(|i| i.parent == self.pubkey)
                    .unwrap_or(false);
            let was = self.bloom_on_tree.insert(pk, on).unwrap_or(false);
            if was && !on {
                // Dropped from the tree: advertise blank so the peer
                // forgets our old bits instead of keeping false positives.
                self.bloom_send.insert(pk, BloomFilter::new());
                self.bloom_dirty.insert(pk, true);
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
        let mut others: Vec<[u8; KEY_LEN]> = self
            .bloom_on_tree
            .iter()
            .filter(|(k, on)| **on && **k != peer)
            .map(|(k, _)| *k)
            .collect();
        others.sort();
        for k in others {
            if let Some(r) = self.bloom_recv.get(&k) {
                b.merge(r);
            }
        }
        if let Some(s) = self.bloom_send.get(&peer) {
            b.merge(s);
        }
        b
    }

    pub(crate) async fn bloom_maintenance<T: Transport>(
        &mut self,
        conn: &mut PeerConn<T>,
        conn_peer: [u8; KEY_LEN],
    ) -> Result<(), crate::error::Error> {
        self.bloom_fix();
        let peers: Vec<[u8; KEY_LEN]> = self
            .bloom_on_tree
            .iter()
            .filter(|(_, on)| **on)
            .map(|(k, _)| *k)
            .collect();
        for pk in peers {
            let b = self.bloom_for(pk);
            if self.bloom_send.get(&pk) != Some(&b) {
                self.bloom_send.insert(pk, b.clone());
                self.bloom_dirty.insert(pk, false);
                let bytes = b.encode();
                self.write_to_peer(
                    conn,
                    conn_peer,
                    pk,
                    crate::frame::FrameType::BloomFilter,
                    &bytes,
                )
                .await?;
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
        if self.bloom_recv.contains_key(&from) {
            self.bloom_recv.insert(from, b);
        }
        Ok(())
    }

    /// Forward a multicast packet along the tree (Go `_sendMulticast`).
    pub(crate) async fn multicast<T: Transport>(
        &mut self,
        conn: &mut PeerConn<T>,
        conn_peer: [u8; KEY_LEN],
        from_key: [u8; KEY_LEN],
        to_key: [u8; KEY_LEN],
        ftype: crate::frame::FrameType,
        payload: &[u8],
    ) -> Result<(), crate::error::Error> {
        let x = xkey(&to_key);
        let mut keys: Vec<[u8; KEY_LEN]> = self
            .bloom_on_tree
            .iter()
            .filter(|(_, on)| **on)
            .map(|(k, _)| *k)
            .collect();
        keys.sort();
        for k in keys {
            if k == from_key {
                continue;
            }
            let interested = self.bloom_recv.get(&k).map(|r| r.test(&x)).unwrap_or(false);
            if !interested {
                continue;
            }
            self.write_to_peer(conn, conn_peer, k, ftype, payload)
                .await?;
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

    fn key(s: &str) -> [u8; KEY_LEN] {
        hexbytes(s).try_into().unwrap()
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
