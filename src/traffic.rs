//! Network traffic packets. Port of `ironwood/network/traffic.go`.
//!
//! Layout: `path + from + source[32] + dest[32] + watermark + payload`,
//! where both paths are zero-terminated port lists. (Go's "not zero
//! terminated" comment is stale: `wireAppendPath` always appends the zero.)

use crate::address::KEY_LEN;
use crate::error::{CoreError, Error};
use crate::frame::{split_path, write_uvarint};
use crate::link::LinkSet;

/// The parts of a traffic frame with no length variation: the two 32-byte keys.
///
/// The paths contribute a terminator each *on top of* their ports, the watermark
/// is a uvarint of any width, and the payload is whatever the session put in the
/// frame — so all three are counted in [`Traffic::encoded_len`] rather than
/// folded into a constant.
const _: () = {
    // A path is at minimum its terminator, so the smallest legal frame is two
    // terminators, two keys and a one-byte watermark. If this constant ever
    // exceeds that, `encoded_len` is wrong in the direction that over-allocates,
    // which is safe; if it is *below* `2 * KEY_LEN` the frame cannot hold its
    // own keys. Assert the floor rather than the ceiling.
    assert!(Traffic::FIXED_LEN >= 2 * KEY_LEN);
};

/// Bytes a zero-terminated port list occupies: each port as a uvarint, plus the
/// terminator.
///
/// The layout is Go's `wireAppendPath` (`network/wire.go:80-86`): ports as
/// uvarints, then a **zero terminator**, unconditionally. Go's own comment in
/// `traffic.go` says "not zero terminated" and is stale — the code has always
/// appended the zero, and a decoder that skipped it would desynchronise on the
/// second path.
fn path_len(path: &[u64]) -> usize {
    path.iter().map(|p| uvarint_len(*p)).sum::<usize>() + 1
}

/// uvarint length of one value.
fn uvarint_len(v: u64) -> usize {
    let mut n = 1;
    let mut rest = v >> 7;
    while rest != 0 {
        n += 1;
        rest >>= 7;
    }
    n
}

/// Write a zero-terminated port list into `out`.
///
/// `out` is assumed large enough; [`Traffic::encode_to`] sizes it with
/// [`path_len`].
fn write_path(out: &mut [u8], path: &[u64]) {
    let mut at = 0;
    for p in path {
        at += write_uvarint(&mut out[at..], *p);
    }
    out[at] = 0;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Traffic {
    pub path: Vec<u64>,
    pub from: Vec<u64>,
    pub source: [u8; KEY_LEN],
    pub dest: [u8; KEY_LEN],
    pub watermark: u64,
    pub payload: Vec<u8>,
}

impl Traffic {
    /// The fixed part of an encoded traffic frame: two path terminators, the two
    /// keys, and the watermark's uvarint.
    ///
    /// Exists so a caller can size one buffer for `encode_to` without doing
    /// arithmetic that has to be kept in step with the layout. The paths and
    /// payload are variable, so this is a *lower* bound and the caller adds them.
    pub const FIXED_LEN: usize = 2 * KEY_LEN;

    /// Bytes `encode_to` will write, exactly.
    ///
    /// Computed rather than a constant because the two paths, the watermark and
    /// the payload are all variable-length. A caller that sizes a buffer with a
    /// stale constant gets a silent truncation, and a `debug_assert` inside
    /// `encode_to` is not a check a `no_std` caller gets to keep.
    pub fn encoded_len(&self) -> usize {
        path_len(&self.path)
            + path_len(&self.from)
            + Self::FIXED_LEN
            + uvarint_len(self.watermark)
            + self.payload.len()
    }

    /// Encode into `out`, returning the byte count.
    ///
    /// The allocating [`encode`](Self::encode) is a wrapper around this, and this
    /// is what a `no_std` caller uses. `out` too small is an error rather than a
    /// truncation, for the reason given on [`frame::encode_frame_to`]: a
    /// truncated traffic frame leaves the far end waiting for bytes that never
    /// come, and the link times out with nothing in the log.
    pub fn encode_to(&self, out: &mut [u8]) -> Result<usize, Error> {
        let need = self.encoded_len();
        if out.len() < need {
            return Err(Error::Core(CoreError::InvalidLength));
        }
        let mut at = 0usize;
        // Written out rather than looped, because the two paths must land in
        // order and threading `&mut &mut [u8]` through a helper would be harder
        // to read than the six lines it saves.
        write_path(&mut out[at..], &self.path);
        at += path_len(&self.path);
        write_path(&mut out[at..], &self.from);
        at += path_len(&self.from);
        out[at..at + KEY_LEN].copy_from_slice(&self.source);
        at += KEY_LEN;
        out[at..at + KEY_LEN].copy_from_slice(&self.dest);
        at += KEY_LEN;
        at += write_uvarint(&mut out[at..], self.watermark);
        out[at..at + self.payload.len()].copy_from_slice(&self.payload);
        at += self.payload.len();
        debug_assert_eq!(at, need, "encoded_len and encode_to disagree");
        Ok(at)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.encoded_len()];
        let n = self
            .encode_to(&mut out)
            .expect("encoded_len sizes the buffer");
        debug_assert_eq!(n, out.len());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let (path, n) = split_path(buf).ok_or(Error::InvalidLength)?;
        let (from, m) = split_path(&buf[n..]).ok_or(Error::InvalidLength)?;
        let rest = &buf[n + m..];
        if rest.len() < 2 * KEY_LEN {
            return Err(Error::Core(CoreError::InvalidLength));
        }
        let mut source = [0u8; KEY_LEN];
        let mut dest = [0u8; KEY_LEN];
        source.copy_from_slice(&rest[..KEY_LEN]);
        dest.copy_from_slice(&rest[KEY_LEN..2 * KEY_LEN]);
        let tail = &rest[2 * KEY_LEN..];
        let (watermark, k) = crate::frame::read_uvarint(tail).ok_or(Error::InvalidLength)?;
        Ok(Self {
            path,
            from,
            source,
            dest,
            watermark,
            payload: tail[k..].to_vec(),
        })
    }
}

impl crate::router::Router {
    /// Handle inbound traffic: forward one hop, deliver session payloads
    /// addressed to us, or report the path broken (Go `router.handleTraffic`).
    pub(crate) async fn handle_inbound_traffic(
        &mut self,
        links: &mut LinkSet,
        tr: &Traffic,
    ) -> Result<(), Error> {
        let mut fwd = tr.clone();
        if let Some(next) = self.greedy_next(links, &fwd.path, &mut fwd.watermark) {
            let buf = fwd.encode();
            return self
                .write_via(links, next, crate::frame::FrameType::Traffic, &buf)
                .await;
        }
        if tr.dest == self.pubkey {
            // Refresh the learned path **before** the session layer, which is
            // where Go does it: `_resetTimeout(tr.source)` at
            // `network/router.go:597`, ahead of `pconn.handleTraffic` on the
            // next line.
            //
            // It was in the session's traffic arm instead, after a successful
            // decrypt, which is a narrower question than the one Go asks. A peer
            // whose every frame either fails to decrypt or is a session `init`
            // never refreshed our entry, so a path that was working aged out
            // after `PATH_TIMEOUT` and the node behind it stopped being reachable
            // over a link that was up. Refreshing on *any* frame addressed to us
            // is also the more sensible rule: the frame arriving is the evidence
            // that the path still works, and whether we could read it says
            // nothing about that.
            if let Some(e) = self.path.entries.get_mut(&tr.source)
                && !e.broken
            {
                e.deadline = std::time::Instant::now() + crate::pathfind::PATH_TIMEOUT;
            }
            return self
                .handle_session_bytes(links, tr.source, &tr.payload)
                .await;
        }
        let broken = crate::pathfind::PathBroken {
            path: tr.from.clone(),
            watermark: u64::MAX,
            source: tr.source,
            dest: tr.dest,
        };
        self.handle_broken(links, &broken).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::KEY_LEN;

    // From Go TestZZVectors: path=[4,2], from=[3,1], watermark=77.
    const TRAFFIC: &str = "0402000301008139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3948a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c4d090807";

    #[test]
    fn traffic_vector_matches_go() {
        let raw = hex::decode(TRAFFIC).unwrap();
        let dec = Traffic::decode(&raw).unwrap();
        assert_eq!(dec.path, vec![4, 2]);
        assert_eq!(dec.from, vec![3, 1]);
        assert_eq!(dec.watermark, 77);
        assert_eq!(dec.payload, vec![9, 8, 7]);
        assert_eq!(hex::encode(dec.encode()), TRAFFIC);
    }

    /// The buffer form must reproduce the **captured Go vector**, not merely
    /// round-trip through our own decoder.
    ///
    /// This is the assertion that matters for the no_std work: `encode_to` is a
    /// second implementation of the layout, and a second implementation that
    /// agrees with the first tells you nothing about whether the first is right.
    /// The Go bytes are the only independent witness available.
    ///
    /// It is also how `encoded_len` is validated. My first version folded the
    /// fixed part into `2 * (1 + 2 * KEY_LEN)`, which double-counted the
    /// terminators and over-ran by 65 bytes — and the `debug_assert_eq!` inside
    /// `encode_to` caught it, which is exactly the assertion's job.
    #[test]
    fn the_buffer_form_reproduces_the_captured_go_vector() {
        let raw = hex::decode(TRAFFIC).unwrap();
        let dec = Traffic::decode(&raw).unwrap();
        let mut buf = vec![0u8; dec.encoded_len()];
        let n = dec.encode_to(&mut buf).expect("encoded_len sizes it");
        assert_eq!(n, raw.len(), "encoded_len is exact");
        assert_eq!(
            hex::encode(&buf[..n]),
            TRAFFIC,
            "the buffer encoder must produce Go's bytes, not ours"
        );
    }

    /// `encoded_len` stays exact as the variable parts vary.
    ///
    /// The three parts that change length — the two paths, the watermark's uvarint
    /// width, and the payload — are each varied across a boundary here. A
    /// `watermark` of 0 versus 127 versus 128 is the interesting one, because a
    /// one-byte-off length function is invisible for small values and truncates
    /// silently for large ones.
    #[test]
    fn encoded_len_is_exact_across_every_variable_part() {
        for path in [vec![], vec![1], vec![1, 2, 3], vec![127], vec![128, 16_384]] {
            for watermark in [0u64, 1, 127, 128, 16_383, 16_384, u64::MAX] {
                for payload_len in [0usize, 1, 127, 128, 1000] {
                    let t = Traffic {
                        path: path.clone(),
                        from: path.clone(),
                        source: [0xABu8; KEY_LEN],
                        dest: [0xCDu8; KEY_LEN],
                        watermark,
                        payload: vec![0x5Au8; payload_len],
                    };
                    let mut buf = vec![0u8; t.encoded_len()];
                    let n = t.encode_to(&mut buf).expect("exact");
                    assert_eq!(n, t.encoded_len(), "len is exact and stable");
                    // And it decodes back to the same thing, which is the only
                    // check that `encoded_len` and `encode_to` agree on *where*
                    // the fields are, not just how many bytes there are.
                    let back = Traffic::decode(&buf[..n]).expect("our own output decodes");
                    assert_eq!(back.path, t.path);
                    assert_eq!(back.from, t.from);
                    assert_eq!(back.watermark, t.watermark);
                    assert_eq!(back.payload, t.payload);
                }
            }
        }
    }

    /// A short buffer is refused, never truncated — for the same reason as
    /// `frame::a_short_buffer_is_refused_rather_than_truncated`, and with the
    /// same stakes: a traffic frame truncated mid-payload is handed to the
    /// session layer, which fails to decrypt it, and the link ages out with
    /// nothing in the log saying why.
    #[test]
    fn a_traffic_frame_is_not_truncated_into_a_short_buffer() {
        let t = Traffic {
            path: vec![1, 2],
            from: vec![3],
            source: [1u8; KEY_LEN],
            dest: [2u8; KEY_LEN],
            watermark: 300,
            payload: vec![7u8; 40],
        };
        let need = t.encoded_len();
        for short in 1..=need {
            let mut buf = vec![0u8; need - short];
            assert!(
                t.encode_to(&mut buf).is_err(),
                "a buffer {short} byte(s) short must be refused"
            );
        }
    }

    /// A learned path is refreshed by **any** frame addressed to us, before the
    /// session layer sees it — Go's `_resetTimeout(tr.source)` at
    /// `network/router.go:597`, one line ahead of `pconn.handleTraffic`.
    ///
    /// The payload here is nonsense, so the session layer decrypts nothing and
    /// discards it. The path entry must still be refreshed: the frame arriving
    /// is the evidence that the path works, and our ability to read it says
    /// nothing about that. When the refresh lived in the session's traffic arm
    /// instead — after a successful decrypt — a peer whose every frame failed to
    /// decrypt aged out of the path table after 60 s over a link that was up,
    /// and the node behind it became unreachable. That is a silent failure of the
    /// worst kind: the link is fine, the peer is fine, and nothing says why.
    #[tokio::test]
    async fn a_path_is_refreshed_by_a_frame_we_cannot_read() {
        let mut router = crate::Router::new(ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]));
        let peer: [u8; KEY_LEN] = [0x21; KEY_LEN];
        // An entry that is already stale, so "was it refreshed" is a fact about
        // the deadline rather than about whether it happened to be fresh.
        router.path.entries.insert(
            peer,
            crate::pathfind::PathEntry {
                path: vec![],
                seq: 1,
                deadline: std::time::Instant::now(),
                broken: false,
            },
        );
        let before = router.path.entries[&peer].deadline;

        let tr = Traffic {
            path: vec![],
            from: vec![],
            source: peer,
            dest: router.pubkey,
            watermark: u64::MAX,
            payload: vec![0xff; 32],
        };
        let mut links = LinkSet::new();
        router
            .handle_inbound_traffic(&mut links, &tr)
            .await
            .expect("an unreadable payload is not an error");

        let after = router.path.entries[&peer].deadline;
        assert!(
            after > before,
            "the frame arriving refreshes the path even though the session \
             discarded it: {before:?} -> {after:?}"
        );
    }

    /// The refresh is for a frame addressed to **us**. A frame in transit is not
    /// evidence that the path *back* from its source works, and refreshing on
    /// one would keep a dead route alive.
    #[tokio::test]
    async fn a_forwarded_frame_does_not_refresh_the_forwarders_path() {
        let mut router = crate::Router::new(ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]));
        let peer: [u8; KEY_LEN] = [0x21; KEY_LEN];
        router.path.entries.insert(
            peer,
            crate::pathfind::PathEntry {
                path: vec![],
                seq: 1,
                deadline: std::time::Instant::now(),
                broken: false,
            },
        );
        let before = router.path.entries[&peer].deadline;

        let tr = Traffic {
            path: vec![],
            from: vec![],
            source: peer,
            dest: [0x33; KEY_LEN],
            watermark: u64::MAX,
            payload: vec![],
        };
        let mut links = LinkSet::new();
        // No next hop and not for us, so this reports the path broken.
        let _ = router.handle_inbound_traffic(&mut links, &tr).await;
        assert_eq!(
            router.path.entries.get(&peer).map(|e| e.deadline),
            Some(before),
            "a transit frame says nothing about the path back from its source"
        );
    }
}
