//! Network traffic packets. Port of `ironwood/network/traffic.go`.
//!
//! Layout: `path + from + source[32] + dest[32] + watermark + payload`,
//! where both paths are zero-terminated port lists. (Go's "not zero
//! terminated" comment is stale: `wireAppendPath` always appends the zero.)

use crate::address::KEY_LEN;
use crate::error::Error;
use crate::frame::{append_path, append_uvarint, split_path};
use crate::link::Link;

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
        conn: &mut dyn Link,
        conn_peer: [u8; KEY_LEN],
        tr: &Traffic,
    ) -> Result<(), Error> {
        let mut fwd = tr.clone();
        if let Some(next) = self.greedy_next(&fwd.path, &mut fwd.watermark) {
            let buf = fwd.encode();
            return self
                .write_to_peer(
                    conn,
                    conn_peer,
                    next,
                    crate::frame::FrameType::Traffic,
                    &buf,
                )
                .await;
        }
        if tr.dest == self.pubkey {
            return self
                .handle_session_bytes(conn, conn_peer, tr.source, &tr.payload)
                .await;
        }
        let broken = crate::pathfind::PathBroken {
            path: tr.from.clone(),
            watermark: u64::MAX,
            source: tr.source,
            dest: tr.dest,
        };
        self.handle_broken(conn, conn_peer, &broken).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
