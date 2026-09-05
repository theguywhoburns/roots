//! Ironwood link framing. Port of `ironwood/network/peers.go` framing +
//! `wire.go` packet types.
//!
//! Each frame: `uvarint(len(type + payload))` + `u8 type` + payload.
//! A keepalive is just `[0x01, 0x01]`.

use crate::error::Error;

/// Max decoded frame body (type + payload). Matches yggdrasil-go's
/// `WithPeerMaxMessageSize(65535 * 2)`.
pub const MAX_MESSAGE_SIZE: usize = 65535 * 2;
/// Keepalive reply delay after inbound non-keepalive traffic (Go: 1s).
pub const KEEPALIVE_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// Link packet types. Discriminants match Go's `wirePacketType` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Dummy = 0,
    KeepAlive = 1,
    SigReq = 2,
    SigRes = 3,
    Announce = 4,
    BloomFilter = 5,
    PathLookup = 6,
    PathNotify = 7,
    PathBroken = 8,
    Traffic = 9,
}

impl FrameType {
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0 => Ok(Self::Dummy),
            1 => Ok(Self::KeepAlive),
            2 => Ok(Self::SigReq),
            3 => Ok(Self::SigRes),
            4 => Ok(Self::Announce),
            5 => Ok(Self::BloomFilter),
            6 => Ok(Self::PathLookup),
            7 => Ok(Self::PathNotify),
            8 => Ok(Self::PathBroken),
            9 => Ok(Self::Traffic),
            _ => Err(Error::InvalidLength),
        }
    }
}

/// Encode `type + payload` with uvarint length prefix.
pub fn encode_frame(ftype: FrameType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    append_uvarint(&mut out, (payload.len() + 1) as u64);
    out.push(ftype as u8);
    out.extend_from_slice(payload);
    out
}

/// The exact bytes Go writes for a keepalive (`{0x01, KeepAlive}`).
pub fn keepalive_bytes() -> [u8; 2] {
    [1, FrameType::KeepAlive as u8]
}

/// Split a full frame body (after the length prefix) into type + payload.
pub fn decode_body(body: &[u8]) -> Result<(FrameType, &[u8]), Error> {
    if body.is_empty() || body.len() > MAX_MESSAGE_SIZE {
        return Err(Error::InvalidLength);
    }
    Ok((FrameType::from_byte(body[0])?, &body[1..]))
}

pub fn append_uvarint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Append a tree path: ports as uvarints plus a zero terminator.
pub fn append_path(out: &mut Vec<u8>, path: &[u64]) {
    for p in path {
        append_uvarint(out, *p);
    }
    append_uvarint(out, 0);
}

/// Split a zero-terminated path prefix. Returns `(ports, bytes_consumed)`.
pub fn split_path(buf: &[u8]) -> Option<(Vec<u64>, usize)> {
    let mut path = Vec::new();
    let mut off = 0;
    loop {
        let (v, n) = read_uvarint(&buf[off..])?;
        off += n;
        if v == 0 {
            break;
        }
        path.push(v);
        if path.len() > 128 {
            return None;
        }
    }
    Some((path, off))
}

/// Returns `(value, bytes_consumed)` or `None` on truncation/overflow.
pub fn read_uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut x: u64 = 0;
    for (i, &b) in buf.iter().enumerate().take(10) {
        if b < 0x80 {
            if i == 9 && b > 1 {
                return None;
            }
            return Some((x | (u64::from(b) << (7 * i as u32)), i + 1));
        }
        x |= u64::from(b & 0x7f) << (7 * i as u32);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_wire_bytes_match_go() {
        // Go: []byte{0x01, byte(wireKeepAlive)}
        assert_eq!(encode_frame(FrameType::KeepAlive, &[]), vec![0x01, 0x01]);
        assert_eq!(keepalive_bytes(), [0x01, 0x01]);
    }

    #[test]
    fn uvarint_roundtrip() {
        for v in [0, 1, 127, 128, 300, 131070, u64::MAX] {
            let mut buf = Vec::new();
            append_uvarint(&mut buf, v);
            assert_eq!(read_uvarint(&buf), Some((v, buf.len())));
        }
        assert_eq!(read_uvarint(&[]), None);
        assert_eq!(read_uvarint(&[0x80]), None);
    }

    #[test]
    fn frame_roundtrip_per_type() {
        let types = [
            FrameType::Dummy,
            FrameType::SigReq,
            FrameType::Announce,
            FrameType::Traffic,
        ];
        for t in types {
            let enc = encode_frame(t, &[9, 8, 7]);
            let (len, n) = read_uvarint(&enc).unwrap();
            assert_eq!(len as usize, enc.len() - n);
            let (dt, payload) = decode_body(&enc[n..]).unwrap();
            assert_eq!(dt, t);
            assert_eq!(payload, &[9, 8, 7]);
        }
    }

    #[test]
    fn rejects_bad_frames() {
        assert!(decode_body(&[]).is_err());
        assert!(decode_body(&[42]).is_err());
        assert!(decode_body(&vec![9u8; MAX_MESSAGE_SIZE + 1]).is_err());
    }
}
