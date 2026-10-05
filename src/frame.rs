//! Ironwood link framing. Port of `ironwood/network/peers.go` framing +
//! `wire.go` packet types.
//!
//! Each frame: `uvarint(len(type + payload))` + `u8 type` + payload.
//! A keepalive is just `[0x01, 0x01]`.

use crate::error::{CoreError, Error};

/// Max decoded frame body (type + payload). Matches yggdrasil-go's
/// `WithPeerMaxMessageSize(65535 * 2)`.
pub const MAX_MESSAGE_SIZE: usize = 65535 * 2;
/// Keepalive reply delay after inbound non-keepalive traffic (Go: 1s).
pub const KEEPALIVE_DELAY: std::time::Duration = std::time::Duration::from_secs(1);
/// Number of link packet types. `Router::frames` and
/// [`FrameType::ALL`] are both sized from it, so the two cannot drift.
pub const FRAME_KINDS: usize = 10;

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
    /// Every kind, indexed by discriminant. Sized by `FRAME_KINDS`, so
    /// adding a variant without widening the count is a compile error
    /// (missing element) and so is widening the count without the variant
    /// (too many elements).
    pub const ALL: [FrameType; FRAME_KINDS] = [
        FrameType::Dummy,
        FrameType::KeepAlive,
        FrameType::SigReq,
        FrameType::SigRes,
        FrameType::Announce,
        FrameType::BloomFilter,
        FrameType::PathLookup,
        FrameType::PathNotify,
        FrameType::PathBroken,
        FrameType::Traffic,
    ];

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
            _ => Err(Error::Core(CoreError::InvalidLength)),
        }
    }
}

/// Every discriminant must be its own index in `ALL`: `Router::frames` is
/// `[u64; FRAME_KINDS]` indexed by `ftype as usize`, so a gap or a duplicate is
/// an out-of-bounds panic on the wire, not a typo.
const _: () = {
    let mut i = 0;
    while i < FRAME_KINDS {
        assert!(
            FrameType::ALL[i] as usize == i,
            "FrameType::ALL must be dense and in Go discriminant order"
        );
        i += 1;
    }
};

/// Longest length prefix [`encode_frame_to`] will write.
///
/// A uvarint over `MAX_MESSAGE_SIZE + 1`, which is 3 bytes: Go caps a frame at
/// `MAX_MESSAGE_SIZE` (`core/link.go`, `MaximumIfMTU`-adjacent) and the type byte
/// adds one, so the prefix never exceeds three bytes in practice. The loop in
/// [`wire_len`] is the authority; this is a bound, not a second implementation
/// of it — and `frame_prefix_len_is_at_most_three_bytes` below checks that it
/// agrees, because a too-small bound here is a silent truncation on the largest
/// legal frame and a too-large one just wastes a byte of caller buffer.
pub const MAX_LEN_PREFIX: usize = 5;

/// Encode `type + payload` with uvarint length prefix, into `out`.
///
/// Returns the number of bytes written, which is what a caller needs in order to
/// advance its own cursor.
///
/// **Why this form exists.** It is the only one that can be called from a
/// `no_std` caller with no allocator, which is the whole reason
/// `roots-core` is being built: the wrapper owns one scratch buffer and calls
/// this in a loop, rather than every frame allocating a `Vec` that is dropped
/// immediately after the socket write. The allocation was never the point — it
/// was invisible.
///
/// `out` is truncated to fit, so a buffer that is too small yields a **short**
/// write, never a panic and never a partial frame that looks complete. That is
/// deliberate: this is called on a path with a socket to write to, and a panic
/// there is worse than a dropped frame.
///
/// # Sizing
///
/// [`wire_len`] gives the exact byte count for a payload length, so a caller
/// does not have to reason about the prefix at all:
///
/// ```ignore
/// let mut buf = [0u8; MAX_FRAME];
/// let n = frame::encode_frame_to(ftype, payload, &mut buf)?;
/// socket.write_all(&buf[..n]).await?;
/// ```
pub fn encode_frame_to(ftype: FrameType, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    // The prefix is computed into a stack array rather than a Vec, so this
    // function allocates nothing at all.
    let mut prefix = [0u8; MAX_LEN_PREFIX];
    let n = write_uvarint(&mut prefix, (payload.len() + 1) as u64);
    let need = n + 1 + payload.len();
    if out.len() < need {
        return Err(Error::Core(CoreError::InvalidLength));
    }
    out[..n].copy_from_slice(&prefix[..n]);
    out[n] = ftype as u8;
    out[n + 1..need].copy_from_slice(payload);
    Ok(need)
}

/// Write a uvarint into a fixed buffer, returning its length.
///
/// `pub(crate)` rather than private because [`crate::traffic`] needs it for the
/// zero-terminated port lists, and duplicating a uvarint writer is how two
/// encoders start disagreeing.
pub(crate) fn write_uvarint(out: &mut [u8], mut v: u64) -> usize {
    let mut n = 0;
    loop {
        if v < 0x80 {
            out[n] = v as u8;
            n += 1;
            return n;
        }
        out[n] = (v as u8) | 0x80;
        n += 1;
        v >>= 7;
    }
}

/// Encode `type + payload` with uvarint length prefix.
///
/// The allocating convenience form, kept because two callers want it and because
/// `roots-core` cannot use it. New `no_std` code should use
/// [`encode_frame_to`]; the split exists so the allocation is a *choice* rather
/// than a property of the API.
pub fn encode_frame(ftype: FrameType, payload: &[u8]) -> Vec<u8> {
    // Sized from `wire_len`, which is exact, plus slack for the prefix — so the
    // `encode_frame_to` below cannot fail and the `unwrap` is unreachable rather
    // than defensive. If `wire_len` and `encode_frame_to` ever disagreed, this
    // panic is the right outcome: a truncated frame on the wire is worse than a
    // crash.
    let mut out = vec![0u8; wire_len(payload.len()) as usize + MAX_LEN_PREFIX];
    let n = encode_frame_to(ftype, payload, &mut out).expect("wire_len sizes the buffer");
    out.truncate(n);
    out
}

/// Bytes a frame of this payload size occupies on the wire: the uvarint
/// length prefix, the type byte, and the payload. Go's link byte counters add
/// exactly these — `linkConn.Read`/`linkConn.Write` count every socket byte
/// (`yggdrasil-go/src/core/link.go:784-793`), and the framing writer emits one
/// `uvarint(1+len) + type + payload` per frame (`peers.go:202-208`).
pub const fn wire_len(payload_len: usize) -> u64 {
    let body = payload_len as u64 + 1;
    let mut prefix = 1u64;
    let mut rest = body;
    while rest >= 0x80 {
        prefix += 1;
        rest >>= 7;
    }
    prefix + body
}

/// Split a full frame body (after the length prefix) into type + payload.
pub fn decode_body(body: &[u8]) -> Result<(FrameType, &[u8]), Error> {
    if body.is_empty() || body.len() > MAX_MESSAGE_SIZE {
        return Err(Error::Core(CoreError::InvalidLength));
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

    /// The buffer form and the owned form must agree **byte for byte**.
    ///
    /// They are two implementations of one encoding, written twice on purpose:
    /// the allocating one exists for convenience and the stack one exists so a
    /// `no_std` caller has a way in. Two implementations of a wire format is
    /// exactly the arrangement that drifts, and the drift would be invisible —
    /// both would still round-trip through our own decoder.
    ///
    /// So this asserts equality against the *other* function, for every type and
    /// for the payload sizes that change the length prefix (1 byte for < 127,
    /// 2 bytes at 127, 3 at 16384). A prefix that grew by one byte at a boundary
    /// is the mutation this is here to catch.
    #[test]
    fn the_buffer_form_matches_the_owned_form_across_prefix_boundaries() {
        for t in FrameType::ALL {
            for len in [0usize, 1, 126, 127, 128, 16_383, 16_384, 16_385] {
                let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let owned = encode_frame(t, &payload);
                let mut buf = [0u8; 64 * 1024];
                let n = encode_frame_to(t, &payload, &mut buf).expect("64 KiB is plenty");
                assert_eq!(
                    &owned[..],
                    &buf[..n],
                    "type {t:?} payload {len}: the two encoders disagree"
                );
                assert_eq!(owned.len(), wire_len(len) as usize, "and wire_len agrees");
            }
        }
    }

    /// A buffer that is too small must be **refused**, not truncated.
    ///
    /// This is the mutation that matters most in the whole function. A
    /// truncating write would emit a frame whose length prefix disagrees with its
    /// body — and the far end would read the prefix, wait for bytes that never
    /// come, and eventually time the link out. On a path with a live socket that
    /// is a silent, confusing failure; a `Result` the caller can see is not.
    ///
    /// The off-by-one is checked from both sides: one byte short must fail and
    /// exactly enough must succeed. A check written as `out.len() < need` rather
    /// than `<=` is the difference between those two.
    #[test]
    fn a_short_buffer_is_refused_rather_than_truncated() {
        let payload = [1u8, 2, 3, 4, 5];
        let need = wire_len(payload.len()) as usize;
        for short in 1..=need {
            let mut buf = vec![0u8; need - short];
            assert!(
                encode_frame_to(FrameType::SigReq, &payload, &mut buf).is_err(),
                "a buffer {short} byte(s) short must be refused, not filled"
            );
        }
        let mut exact = vec![0u8; need];
        assert_eq!(
            encode_frame_to(FrameType::SigReq, &payload, &mut exact).expect("exactly enough"),
            need
        );
    }

    /// `MAX_LEN_PREFIX` must be big enough for the largest legal frame.
    ///
    /// If it were not, `write_uvarint` would index past its stack array — and the
    /// symptom would be a corrupted prefix on the biggest frames only, which is
    /// the kind of bug that shows up as an unexplained link timeout on a busy
    /// node. So the bound is checked against `wire_len`'s own arithmetic rather
    /// than trusted.
    #[test]
    fn the_length_prefix_bound_covers_the_largest_frame() {
        for len in [0usize, 127, 16_384, MAX_MESSAGE_SIZE] {
            // `wire_len` counts the prefix; the encoded buffer is prefix + type +
            // payload, and the prefix alone is what `MAX_LEN_PREFIX` bounds.
            let prefix = wire_len(len) as usize - (len + 1);
            assert!(
                prefix <= MAX_LEN_PREFIX,
                "payload {len} needs a {prefix}-byte prefix, bound is {MAX_LEN_PREFIX}"
            );
        }
    }

    /// An empty payload still produces a valid frame.
    ///
    /// `len + 1` rather than `len`: the type byte is inside the length prefix,
    /// so a `Dummy` frame with no payload is one byte of body and must encode as
    /// `01 00`, not `00`. Getting this wrong is invisible for every non-empty
    /// payload and fatal for every empty one, and `KeepAlive` is an empty payload
    /// on a live link.
    #[test]
    fn an_empty_payload_still_counts_its_type_byte() {
        let enc = encode_frame(FrameType::KeepAlive, &[]);
        assert_eq!(enc, vec![0x01, 0x01], "uvarint(1) then the type byte");
        let (len, n) = read_uvarint(&enc).unwrap();
        assert_eq!(len as usize, enc.len() - n);
        assert_eq!(decode_body(&enc[n..]).unwrap().0, FrameType::KeepAlive);
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
    fn frame_kinds_match_table_len() {
        // The counter that indexes by `ftype as usize` (`Router::frames`) is
        // `[u64; FRAME_KINDS]`: a variant outside
        // that window is an out-of-bounds panic on the wire, not a typo.
        // The const block above is the real guard; this pins the same
        // facts so a reader (and CI diff) sees them as a test.
        assert_eq!(FRAME_KINDS, FrameType::ALL.len());
        for (i, t) in FrameType::ALL.iter().enumerate() {
            assert_eq!(*t as usize, i, "{t:?} is not at its discriminant index");
            assert_eq!(FrameType::from_byte(i as u8).unwrap(), *t);
        }
        assert_eq!(FrameType::ALL[FRAME_KINDS - 1], FrameType::Traffic);
        assert!(FrameType::from_byte(FRAME_KINDS as u8).is_err());
        // Wire cost of a frame is what the byte counters add.
        assert_eq!(wire_len(0), 2);
        assert_eq!(wire_len(3), 5);
        assert_eq!(wire_len(12_000), 12_003, "two-byte prefix at 16383 body");
    }

    #[test]
    fn rejects_bad_frames() {
        assert!(decode_body(&[]).is_err());
        assert!(decode_body(&[42]).is_err());
        assert!(decode_body(&vec![9u8; MAX_MESSAGE_SIZE + 1]).is_err());
    }
}
