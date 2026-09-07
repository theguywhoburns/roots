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

/// Per-link tree state, one entry per peer key.
pub(crate) struct PeerState {
    /// Our local port number for this link (we number from 1).
    pub(crate) port: u64,
    pub(crate) req: SigReq,
    pub(crate) responded: bool,
    pub(crate) lag: std::time::Duration,
    pub(crate) sent_at: Option<std::time::Instant>,
    /// Link priority from the handshake (lowest wins among same-key links).
    pub(crate) prio: u8,
    /// Connection order (oldest wins final tiebreaks).
    pub(crate) order: u64,
    /// Which implementation the peer runs (for gating behavior fixes).
    pub(crate) kind: PeerKind,
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
