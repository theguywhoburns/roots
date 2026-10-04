//! The core error type: everything that can go wrong **in a wire format or a
//! state machine**, and nothing that needs `std` to describe.
//!
//! # Why this is not just `roots::Error`
//!
//! The wrapper's `Error` has an `Io(#[from] std::io::Error)` variant, because a
//! socket can fail. This one cannot name `std::io::Error`: a `no_std` core has
//! no `io`, and faking one with an integer would throw away the only part of an
//! I/O error anybody reads.
//!
//! So the split is by *cause*, and it is the same split the rest of the crate
//! uses — a thing that needs the outside world goes to the wrapper:
//!
//! * here: every refusal that is a *protocol* fact. A bad signature, a wrong
//!   version, a length that cannot be what it claims to be. These are decided
//!   entirely by the bytes, so they are decidable with no allocator and no
//!   system.
//! * in `roots`: anything that needs a descriptor, a buffer or a filesystem.
//!
//! A caller matching both matches [`Error::is_link`] and then its own I/O
//! variant, which is why that one method is the only thing duplicated across
//! the split.
//!
//! # Display without `alloc`
//!
//! # One thing this type cannot do, and why
//!
//! A `std` caller will want `impl std::error::Error for roots_core::Error`, so
//! they can put one in a `Box<dyn Error>` and walk its `source` chain. That impl
//! **cannot live here**, and the reason is worth stating because it reads like a
//! contradiction: `core::error::Error` is unstable, and `std::error::Error` is in
//! `std`.
//!
//! But `std::error::Error` has no `std`-only supertraits — it needs `Debug` and
//! `Display`, both `core` traits, plus a `description` method with a default. So
//! the only thing an impl needs from `std` is the *name* of the trait, and this
//! crate cannot name it.
//!
//! The fix is the standard one and costs one line: the shim lives in the wrapper,
//! where `std` exists. `roots::Error::Core(..)` carries it, and that type's
//! `source()` returns the inner error, so the chain a reporter walks is unchanged
//! for anyone who goes through the wrapper. One unstable attribute, not a design
//! decision.
//!
//! `thiserror`'s generated `Display` is `core::fmt`, which is fine under
//! `no_std` — it is `std::fmt::Error` and `std` error *sources* that need an
//! allocator. The variants carrying text are therefore the awkward ones:
//! `BadUri` holds a `String` in the wrapper because a URI is parsed from user
//! input and reported back verbatim (the admin socket puts it in an `error`
//! field that `yggdrasilctl` prints). Core does not parse URIs — that is
//! `link`'s job, and `link` is in the wrapper — so core has no `BadUri` at
//! all, and this file is written by hand rather than derived.

use core::fmt;

/// Every protocol-level refusal.
///
/// Deliberately **not** `#[derive(thiserror::Error)]`: the derive would be fine
/// (`core::fmt` is enough), but a hand-written `Display` lets each string carry
/// the Go citation that makes it checkable, which is the convention the rest of
/// this crate follows and the reason these strings are load-bearing rather than
/// decorative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The preamble was not `meta`, so this is not a Yggdrasil peer.
    ///
    /// Go: `linkErrorInvalidPreamble = "invalid handshake, remote side is not
    /// Yggdrasil"` (`core/link.go:149`).
    InvalidPreamble,
    /// A length field disagrees with the bytes present.
    ///
    /// Go: `linkErrorInvalidLength = "invalid handshake length, possible
    /// version mismatch"` (`:150`).
    InvalidLength,
    /// The password did not match the remote side's.
    ///
    /// Go: `linkErrorPasswordMismatch` (`:152`).
    BadPassword,
    /// The remote speaks a protocol version we do not.
    ///
    /// The two numbers are (theirs, ours) — Go's error carries both, and
    /// `yggdrasilctl` shows them, so the order is part of the contract.
    ///
    /// Go: `linkErrorBadVersion = "incompatible version %v.%v, expected 0.5"`
    /// (`:151`).
    BadVersion(u16, u16),
    /// A node may not link to itself.
    ///
    /// Go: `linkErrorLinkToSelf = "node cannot connect to self"` (`:153`), raised
    /// in `ErrLinkToSelf` when a `meta` carries our own key (`core/link.go:662`).
    SelfDial,
    /// The peer's key is not in `AllowedPublicKeys`.
    KeyNotAllowed,
    /// A pinned key did not match the one presented.
    PinnedMismatch,
    /// A password longer than 64 bytes.
    ///
    /// The bound is the SHA-256 block the membership hash is built from, so it is
    /// a property of the construction rather than a policy limit.
    PasswordTooLong,

    // The five URI refusals below are Go's `linkError` constants verbatim
    // (`core/link.go:154-157`) rather than ours, because `addPeer` puts the
    // string straight into the admin socket's `error` field where
    // `yggdrasilctl` displays it. Changing one changes what an operator sees.
    /// Go: `linkErrorUnknownSchema = "link schema unknown"`.
    UnrecognisedSchema,
    /// Go: `linkErrorPinnedKeyInvalid = "pinned public key is invalid"`.
    PinnedKeyInvalid,
    /// Go: `linkErrorPriorityInvalid = "priority value is invalid"`.
    PriorityInvalid,
    /// Go: `linkErrorInvalidPassword = "invalid password supplied"`.
    PasswordInvalid,
    /// Go: `linkErrorInvalidMaxBackoff = "max backoff duration invalid"`.
    MaxBackoffInvalid,

    /// A `ws://` peer did not offer the `ygg-ws` subprotocol.
    BadSubprotocol,
    /// A handshake did not complete in time.
    Timeout,
    /// There is no live link to the requested peer.
    ///
    /// This is a *routing* fact, not a protocol one: it means the send had
    /// nowhere to go. It is the error a soft send reports instead of dropping
    /// the payload silently.
    NoLink,
}

impl Error {
    /// True for errors that mean **"this link is gone"** rather than "this node
    /// is broken".
    ///
    /// The distinction is load-bearing for liveness: a node loop keeps serving
    /// its surviving links and redials on these, whereas anything else is a bug
    /// worth stopping for. Go gets this for free from structure — a dead peer's
    /// reader goroutine just returns and `removePeer` cleans up
    /// (`peers.go:228`) — which is why one dead link never stops its siblings
    /// there.
    ///
    /// Core can only report the protocol half (`NoLink`). The wrapper's version
    /// additionally reports its I/O errors, because those are what a real socket
    /// produces when a peer disappears; this method exists so that a caller
    /// matching both does not have to remember which half it is holding.
    pub fn is_link(&self) -> bool {
        matches!(self, Error::NoLink)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every string here is either Go's verbatim or a restatement of it, and
        // `tests/go_vectors.rs` / `21-admin.md` pin the ones a user can see.
        // A test asserts these against Go's own text, so a reword is a failure
        // rather than a cosmetic change.
        let s = match self {
            Error::InvalidPreamble => "invalid handshake, remote side is not Yggdrasil",
            Error::InvalidLength => "invalid handshake length, possible version mismatch",
            Error::BadPassword => "password does not match remote side",
            Error::BadVersion(theirs, ours) => {
                return write!(f, "incompatible version {theirs}.{ours}, expected 0.5");
            }
            Error::SelfDial => "node cannot connect to self",
            Error::KeyNotAllowed => "remote key not in allowlist",
            Error::PinnedMismatch => "pinned key mismatch",
            Error::PasswordTooLong => "password longer than 64 bytes",
            Error::UnrecognisedSchema => "link schema unknown",
            Error::PinnedKeyInvalid => "pinned public key is invalid",
            Error::PriorityInvalid => "priority value is invalid",
            Error::PasswordInvalid => "invalid password supplied",
            Error::MaxBackoffInvalid => "max backoff duration invalid",
            Error::BadSubprotocol => "websocket subprotocol mismatch, expected ygg-ws",
            Error::Timeout => "handshake timed out",
            Error::NoLink => "no open link to this peer",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render into a fixed buffer. There is no `to_string` here and cannot be:
    /// `ToString` is blanket-implemented for anything `Display`, and it is
    /// `alloc`-gated, so asking for it is a compile error.
    ///
    /// That is not a limitation to work around in the tests — it is the property
    /// under test elsewhere in this crate, and having the *tests* hit it too is
    /// a useful reminder that nothing in `roots-core` may quietly grow a `String`.
    struct Fixed {
        buf: [u8; 96],
        len: usize,
    }

    impl Fixed {
        fn new() -> Self {
            Fixed {
                buf: [0u8; 96],
                len: 0,
            }
        }
        fn render(&mut self, e: &Error) -> &str {
            core::fmt::write(self, format_args!("{e}")).unwrap();
            core::str::from_utf8(&self.buf[..self.len]).unwrap()
        }
    }

    impl core::fmt::Write for Fixed {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            assert!(
                self.len + s.len() <= self.buf.len(),
                "the 96-byte buffer is too small for this message"
            );
            self.buf[self.len..self.len + s.len()].copy_from_slice(s.as_bytes());
            self.len += s.len();
            Ok(())
        }
    }

    /// Go's exact strings for the variants whose text a user can see, read out of
    /// the pinned `reference/yggdrasil-go/src/core/link.go:149-157`.
    ///
    /// This is the test that makes the hand-written `Display` above safe. It is
    /// deliberately **not** a round trip through our own encoder: that would pass
    /// for any wording at all, which is exactly the failure mode — a reworded
    /// string that still satisfies our own tests and is wrong in
    /// `yggdrasilctl`.
    #[test]
    fn the_strings_are_go_s_verbatim() {
        let cases: &[(Error, &str)] = &[
            (
                Error::InvalidPreamble,
                "invalid handshake, remote side is not Yggdrasil",
            ),
            (
                Error::InvalidLength,
                "invalid handshake length, possible version mismatch",
            ),
            (Error::BadPassword, "password does not match remote side"),
            (
                Error::BadVersion(1, 5),
                "incompatible version 1.5, expected 0.5",
            ),
            (Error::SelfDial, "node cannot connect to self"),
            (Error::UnrecognisedSchema, "link schema unknown"),
            (Error::PinnedKeyInvalid, "pinned public key is invalid"),
            (Error::PriorityInvalid, "priority value is invalid"),
            (Error::PasswordInvalid, "invalid password supplied"),
            (Error::MaxBackoffInvalid, "max backoff duration invalid"),
        ];
        let mut f = Fixed::new();
        for (err, want) in cases {
            f.len = 0;
            assert_eq!(f.render(err), *want, "for {err:?}");
        }
    }

    /// `BadVersion` carries two numbers and they are **not** interchangeable: the
    /// remote's version first, ours second. Go's format string is
    /// `"incompatible version %v.%v, expected 0.5"` with (theirs, ours) in that
    /// order (`core/link.go:151`), and an operator reading this needs to know
    /// which side is wrong.
    ///
    /// The mutation this kills is swapping the two arguments, which compiles
    /// cleanly and reports a plausible-looking but backwards version.
    #[test]
    fn bad_version_names_theirs_first() {
        // Both orders are rendered into separate buffers rather than compared
        // inline, because a `Fixed` borrow cannot outlive the `assert_ne!` arm
        // that would reset it — and because two explicit renders read better
        // than one render hidden inside an assertion.
        let mut theirs = Fixed::new();
        assert_eq!(
            theirs.render(&Error::BadVersion(0, 5)),
            "incompatible version 0.5, expected 0.5"
        );
        let mut ours = Fixed::new();
        assert_eq!(
            ours.render(&Error::BadVersion(5, 0)),
            "incompatible version 5.0, expected 0.5",
            "the remote's version comes first; ours is the fixed 'expected 0.5'"
        );
        assert_ne!(
            theirs.buf, ours.buf,
            "swapping the two arguments must change the message"
        );
    }

    /// Only `NoLink` is core's "this link is gone".
    ///
    /// A protocol refusal is **not** a dead link: `InvalidLength` means the peer
    /// is talking nonsense, which no amount of redialing will fix, so a node loop
    /// that treated it as retryable would spin forever against a misconfigured
    /// peer. This is the classification the node loop uses to decide whether to
    /// keep serving its surviving links, so the negative cases are worth saying
    /// out loud.
    #[test]
    fn only_no_link_means_the_link_is_gone() {
        assert!(Error::NoLink.is_link());
        for fatal in [
            Error::InvalidPreamble,
            Error::InvalidLength,
            Error::BadPassword,
            Error::SelfDial,
            Error::KeyNotAllowed,
            Error::PinnedMismatch,
            Error::PasswordTooLong,
            Error::Timeout,
        ] {
            assert!(!fatal.is_link(), "{fatal:?} must not read as a dead link");
        }
    }

    /// Every variant renders to something non-empty.
    ///
    /// An empty `error` field in the admin socket is indistinguishable from "no
    /// error", which is the failure mode `Error` exists to prevent — so the check
    /// is not "is the text right" (that is the test above) but "is there any text
    /// at all", for the variants the other test does not enumerate.
    #[test]
    fn every_variant_renders_something() {
        let all = [
            Error::InvalidPreamble,
            Error::InvalidLength,
            Error::BadPassword,
            Error::BadVersion(0, 5),
            Error::SelfDial,
            Error::KeyNotAllowed,
            Error::PinnedMismatch,
            Error::PasswordTooLong,
            Error::UnrecognisedSchema,
            Error::PinnedKeyInvalid,
            Error::PriorityInvalid,
            Error::PasswordInvalid,
            Error::MaxBackoffInvalid,
            Error::BadSubprotocol,
            Error::Timeout,
            Error::NoLink,
        ];
        let mut f = Fixed::new();
        for e in all {
            f.len = 0;
            let got = f.render(&e);
            assert!(!got.is_empty(), "{e:?} renders nothing");
            // And it must not render the variant name either: a `Debug`-shaped
            // fallback would satisfy "non-empty" while showing a Rust name to an
            // operator, which is worse than nothing.
            assert!(
                !got.contains("Error::"),
                "{e:?} rendered a Rust variant name: {got}"
            );
        }
    }
}
