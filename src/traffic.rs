//! Network traffic packets. Port of `ironwood/network/traffic.go`.
//!
//! Layout: `path + from + source[32] + dest[32] + watermark + payload`,
//! where both paths are zero-terminated port lists. (Go's "not zero
//! terminated" comment is stale: `wireAppendPath` always appends the zero.)

use crate::address::KEY_LEN;
use crate::error::Error;
use crate::frame::{append_path, append_uvarint, split_path};
use crate::link::LinkSet;

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
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        append_path(&mut out, &self.path);
        append_path(&mut out, &self.from);
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
        append_uvarint(&mut out, self.watermark);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let (path, n) = split_path(buf).ok_or(Error::InvalidLength)?;
        let (from, m) = split_path(&buf[n..]).ok_or(Error::InvalidLength)?;
        let rest = &buf[n + m..];
        if rest.len() < 2 * KEY_LEN {
            return Err(Error::InvalidLength);
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
