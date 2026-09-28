//! Peer identity on a link: Go vs roots differentiation.
//!
//! Go's `meta` decoder ignores unknown TLV tags (no `default` arm in
//! `yggdrasil-go/src/core/version.go` `decode`, fields are just skipped),
//! and the handshake signature only covers the public key, so extra TLVs are
//! safe to add: Go peers ignore them, roots peers read them.
//!
//! We advertise `TAG_VENDOR="roots"` + `TAG_FEATURES` bitflags. Absence of
//! the vendor tag means a Go (or other) peer. All behavior fixes must be
//! gated on `PeerKind::supports(_)`, defaulting to Go-exact wire behavior.

use crate::tree::SigReq;

/// TLV tag: implementation name, UTF-8 (e.g. `roots`). Unknown to Go.
pub const TAG_VENDOR: u16 = 4;
/// TLV tag: feature bitflags, BE32. Unknown to Go.
pub const TAG_FEATURES: u16 = 5;
/// Our vendor string.
pub const VENDOR_ROOTS: &[u8] = b"roots";
/// Max vendor bytes accepted (hygiene cap; longer values fall back to Go).
pub const VENDOR_MAX: usize = 32;

/// Feature flags for roots-to-roots behavior fixes. Zero means Go-exact.
/// New fixes allocate a bit and gate on `supports()`.
pub mod feat {
    /// Placeholder: no roots-only behavior enabled yet.
    pub const NONE: u32 = 0;
}

/// Which implementation sits on the other end of a link.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PeerKind {
    /// Go (or unknown): no vendor tag, or a non-roots vendor. Always gets
    /// Go-exact wire behavior.
    #[default]
    Go,
    /// Roots peer with advertised feature bits.
    Roots { features: u32 },
}

impl PeerKind {
    /// From decoded handshake TLVs (`None` = tag absent).
    pub fn from_tlvs(vendor: Option<&[u8]>, features: Option<u32>) -> Self {
        match vendor {
            Some(v) if v == VENDOR_ROOTS => Self::Roots {
                features: features.unwrap_or(feat::NONE),
            },
            _ => Self::Go,
        }
    }

    /// True for roots peers advertising `flag`.
    pub fn supports(&self, flag: u32) -> bool {
        match self {
            Self::Go => false,
            Self::Roots { features } => features & flag == flag,
        }
    }

    /// True when the peer is a roots client (any version).
    pub fn is_roots(&self) -> bool {
        matches!(self, Self::Roots { .. })
    }
}

/// Per-node-key tree state: the two fields ironwood keys by `publicKey`
/// rather than by `*peer`.
///
/// Go splits the two halves deliberately (`network/router.go:50-56`): `ports`,
/// `requests`, `responses`, `sent` and `infos` are per key, while `lags`,
/// `responded` and a `peer`'s own `srst`/`srrt`/`prio`/`order` are per
/// connection. Two links to one node therefore share a port and a request, and
/// nothing else. Keying everything by node key, as this type used to, made the
/// second link's round trip overwrite the first's.
pub(crate) struct PeerState {
    /// Our local port number for this key (we number from 1). Shared by every
    /// link to it, so a reconnect keeps the port a redial does not look new.
    pub(crate) port: u64,
    /// The open request for this key, shared for the same reason
    /// (`r.requests[pk]`, `router.go:120-124`).
    pub(crate) req: SigReq,
}

/// Per-link tree state, one entry per [`crate::link::LinkId`].
///
/// Everything Go hangs off `*peer` (`router.go:53-56`): the lag EWMA, whether
/// this link has answered, the handshake priority, the connection order, the
/// round-trip pair `getPeers` reports as `latency`, and the peer's vendor tag.
pub(crate) struct LinkState {
    /// The node key this link speaks for. Several links may share one.
    pub(crate) peer: [u8; 32],
    /// True once this link answered one of our `SigReq`s (`r.responded[p]`).
    pub(crate) responded: bool,
    /// The lag EWMA: `routerUnknownLatency` until the first round trip, then
    /// seeded at `rtt*2` and eased 7/8 toward the stored timestamps
    /// (`router.go:433-441`).
    pub(crate) lag: std::time::Duration,
    /// When we sent the request we are waiting on, in Go's `srst`
    /// (`peers.go:112-113`).
    pub(crate) sent_at: Option<std::time::Instant>,
    /// Link priority from the handshake (lowest wins among candidates).
    pub(crate) prio: u8,
    /// Connection order (oldest wins final tiebreaks).
    pub(crate) order: u64,
    /// Which implementation the peer runs (for gating behavior fixes).
    pub(crate) kind: PeerKind,
    /// When the last `SigRes` that passed its signature check arrived, Go's
    /// `srrt`. `getPeers`' `latency` is `srrt - srst` **re-read at query time**
    /// (`debug.go:85`), so it is the last round trip as of now, not as of the
    /// reply — and grows until the next `SigReq` resets the pair.
    pub(crate) srrt: Option<std::time::Instant>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_vendor_is_go() {
        assert_eq!(PeerKind::from_tlvs(None, None), PeerKind::Go);
        assert_eq!(PeerKind::from_tlvs(Some(b"yggdrasil"), None), PeerKind::Go);
        assert!(!PeerKind::Go.supports(u32::MAX));
        assert!(!PeerKind::Go.is_roots());
    }

    #[test]
    fn roots_vendor_parses_features() {
        let k = PeerKind::from_tlvs(Some(b"roots"), Some(0));
        assert!(k.is_roots());
        assert!(!k.supports(1));
        let k = PeerKind::from_tlvs(Some(b"roots"), None);
        assert_eq!(k, PeerKind::Roots { features: 0 });
    }

    #[test]
    fn oversize_vendor_is_go() {
        // Overlong values are rejected at decode time; from_tlvs sees only
        // capped inputs, but a foreign vendor must still map to Go.
        assert_eq!(PeerKind::from_tlvs(Some(b"roots!"), None), PeerKind::Go);
    }

    #[test]
    fn key_len_reexport_sanity() {
        let _: [u8; 32] = [0u8; 32];
    }
}
